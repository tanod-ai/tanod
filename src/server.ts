import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createAdapterRegistry, type ToolAdapter } from './adapters.js';
import { AuditLog } from './audit.js';
import { hashArguments } from './canonical.js';
import type { DecisionResponse, PolicyFile, ToolCallRequest } from './domain.js';
import { executeGovernedToolCall, type ExecutionInput } from './execution.js';
import { evaluatePolicy, loadPolicyFile } from './policy.js';
import { MAX_APPROVAL_TTL_SECONDS, generateSigningKeyPair, normalizeApprovalTtl, signApproval, verifyApprovalToken } from './signing.js';
import { createStorageFromEnv, type ApprovalRequestRecord, type ApprovalStatus, type Storage } from './storage.js';

const MAX_REQUEST_BODY_BYTES = 1024 * 1024;

export interface ServerConfig {
  host: string;
  port: number;
  policyFile: string;
  auditFile: string;
  privateKeyFile: string;
  publicKeyFile: string;
  enableShellExecution: boolean;
  shellTimeoutMs: number;
  httpTimeoutMs: number;
  allowPrivateNetworkHttp?: boolean;
  apiKeys: string[];
  apiKeyRoles?: Record<string, string[]>;
  apiKeyIdentities?: Record<string, string>;
}

interface AuthContext {
  authenticated: boolean;
  key?: string;
  subject?: string;
  roles: string[];
}

class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

export async function startServer(config: ServerConfig): Promise<Server> {
  const policyFile = await loadPolicyFile(config.policyFile);
  const storage = createStorageFromEnv(process.env);
  await storage.initialize();
  const auditLog = new AuditLog(config.auditFile, storage);
  const keys = await loadOrCreateKeys(config.privateKeyFile, config.publicKeyFile);
  const adapters = createAdapterRegistry({
    enableShellExecution: config.enableShellExecution,
    shellTimeoutMs: config.shellTimeoutMs,
    httpTimeoutMs: config.httpTimeoutMs,
    allowPrivateNetworkHttp: config.allowPrivateNetworkHttp === true,
  });

  const server = createServer(async (request, response) => {
    try {
      writeCorsHeaders(response);
      if (request.method === 'OPTIONS') {
        response.writeHead(204);
        response.end();
        return;
      }
      const auth = getAuthContext(request, config.apiKeys, config.apiKeyRoles ?? {}, config.apiKeyIdentities ?? {});
      if (!auth.authenticated) {
        json(response, 401, { error: 'unauthorized' });
        return;
      }
      await route(request, response, policyFile, auditLog, keys, adapters, storage, auth);
    } catch (error) {
      const statusCode = error instanceof HttpError ? error.statusCode : error instanceof SyntaxError ? 400 : 500;
      json(response, statusCode, { error: error instanceof Error ? error.message : 'unknown error' });
    }
  });

  await new Promise<void>((resolve) => server.listen(config.port, config.host, resolve));
  console.log(`tanod gateway listening on http://${config.host}:${config.port}`);
  return server;
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  policyFile: PolicyFile,
  auditLog: AuditLog,
  keys: { privateKeyPem: string; publicKeyPem: string },
  adapters: Map<string, ToolAdapter>,
  storage: Storage,
  auth: AuthContext,
): Promise<void> {
  const method = request.method ?? 'GET';
  const url = new URL(request.url ?? '/', 'http://localhost');

  if (method === 'GET' && url.pathname === '/healthz') {
    json(response, 200, { status: 'ok', service: 'tanod-gateway', adapters: [...adapters.keys()] });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/decisions') {
    const toolCall = await readJson<ToolCallRequest>(request);
    validateToolCall(toolCall);
    const decision = evaluatePolicy(policyFile, toolCall);
    await storage.recordDecision(toolCall, decision);
    await auditDecision(auditLog, toolCall, decision);
    json(response, 200, decision);
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/approvals') {
    const body = await readJson<{
      request: ToolCallRequest;
      approved_by: string;
      approved_role?: string;
      policy_id?: string;
      ttl_seconds?: number;
    }>(request);
    validateToolCall(body.request);
    const decision = evaluatePolicy(policyFile, body.request);
    if (decision.decision !== 'require_approval') {
      json(response, 409, { error: `Request decision is ${decision.decision}; approval token not required.` });
      return;
    }
    const approvedRole = validateApprover(body.approved_by, body.approved_role, decision, auth);
    const ttlSeconds = resolveApprovalTtl(body.ttl_seconds, decision);
    const policyId = decision.policy_ids[0] ?? 'manual';
    const { token, claims } = signApproval(
      {
        request: body.request,
        approved_by: body.approved_by,
        approved_role: approvedRole,
        policy_id: policyId,
        risk_level: decision.risk_level,
        ttl_seconds: ttlSeconds,
      },
      keys.privateKeyPem,
    );
    await auditLog.append({
      event_type: 'approval.signed',
      request_id: body.request.request_id,
      actor_id: body.approved_by,
      agent_id: body.request.agent.agent_id,
      tool_name: body.request.tool.name,
      risk_level: decision.risk_level,
      policy_ids: decision.policy_ids,
      argument_hash: claims.tool_args_hash,
      approval_id: claims.approval_id,
      details: { approved_role: approvedRole, expires_at: new Date(claims.exp * 1000).toISOString() },
    });
    json(response, 200, { approval_token: token, argument_hash: claims.tool_args_hash, expires_at: new Date(claims.exp * 1000).toISOString() });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/approval-requests') {
    const body = await readJson<{ request: ToolCallRequest; requested_by?: string }>(request);
    validateToolCall(body.request);
    const decision = evaluatePolicy(policyFile, body.request);
    await storage.recordDecision(body.request, decision);
    await auditDecision(auditLog, body.request, decision);
    if (decision.decision !== 'require_approval') {
      json(response, 409, { error: `Request decision is ${decision.decision}; approval request not required.`, decision });
      return;
    }
    const record = await storage.createApprovalRequest({
      request: body.request,
      decision,
      requested_by: body.requested_by ?? body.request.actor.user_id,
    });
    await auditLog.append({
      event_type: 'approval.requested',
      request_id: body.request.request_id,
      actor_id: record.requested_by,
      agent_id: body.request.agent.agent_id,
      tool_name: body.request.tool.name,
      decision: decision.decision,
      risk_level: decision.risk_level,
      policy_ids: decision.policy_ids,
      argument_hash: decision.argument_hash,
      approval_id: record.approval_id,
      result: 'blocked',
    });
    json(response, 202, record);
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/approval-requests') {
    const status = url.searchParams.get('status') as ApprovalStatus | null;
    const records = await storage.listApprovalRequests(status ?? undefined);
    json(response, 200, { approval_requests: records });
    return;
  }

  const approvalApproveMatch = method === 'POST' ? url.pathname.match(/^\/v1\/approval-requests\/([^/]+)\/approve$/) : null;
  if (approvalApproveMatch) {
    const approvalId = decodeURIComponent(approvalApproveMatch[1]);
    const body = await readJson<{ approved_by: string; approved_role?: string; ttl_seconds?: number }>(request);
    const record = await getPendingApproval(storage, approvalId);
    const approvedRole = validateApprover(body.approved_by, body.approved_role, record.decision, auth);
    const ttlSeconds = resolveApprovalTtl(body.ttl_seconds, record.decision);
    const policyId = record.decision.policy_ids[0] ?? 'manual';
    const { token, claims } = signApproval(
      {
        request: record.request,
        approved_by: body.approved_by,
        approved_role: approvedRole,
        policy_id: policyId,
        risk_level: record.decision.risk_level,
        ttl_seconds: ttlSeconds,
        approval_id: record.approval_id,
      },
      keys.privateKeyPem,
    );
    const updated = await storage.approveApprovalRequest(approvalId, {
      approved_by: body.approved_by,
      approved_role: approvedRole,
      approval_token: token,
      expires_at: new Date(claims.exp * 1000).toISOString(),
    });
    await auditLog.append({
      event_type: 'approval.approved',
      request_id: record.request_id,
      actor_id: body.approved_by,
      agent_id: record.request.agent.agent_id,
      tool_name: record.request.tool.name,
      decision: record.decision.decision,
      risk_level: record.decision.risk_level,
      policy_ids: record.decision.policy_ids,
      argument_hash: claims.tool_args_hash,
      approval_id: record.approval_id,
      result: 'success',
      details: { approved_role: approvedRole, expires_at: updated.expires_at },
    });
    json(response, 200, updated);
    return;
  }

  const approvalRejectMatch = method === 'POST' ? url.pathname.match(/^\/v1\/approval-requests\/([^/]+)\/reject$/) : null;
  if (approvalRejectMatch) {
    const approvalId = decodeURIComponent(approvalRejectMatch[1]);
    const body = await readJson<{ rejected_by: string; reason?: string }>(request);
    if (!body.rejected_by) throw new HttpError(400, 'rejected_by is required.');
    validateAuthSubject(body.rejected_by, auth);
    const record = await getPendingApproval(storage, approvalId);
    const updated = await storage.rejectApprovalRequest(approvalId, { rejected_by: body.rejected_by, reason: body.reason });
    await auditLog.append({
      event_type: 'approval.rejected',
      request_id: record.request_id,
      actor_id: body.rejected_by,
      agent_id: record.request.agent.agent_id,
      tool_name: record.request.tool.name,
      decision: record.decision.decision,
      risk_level: record.decision.risk_level,
      policy_ids: record.decision.policy_ids,
      argument_hash: record.argument_hash,
      approval_id: record.approval_id,
      result: 'blocked',
      details: { reason: body.reason },
    });
    json(response, 200, updated);
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/approval-verifications') {
    const body = await readJson<{ request: ToolCallRequest; approval_token: string }>(request);
    validateToolCall(body.request);
    const decision = evaluatePolicy(policyFile, body.request);
    const claims = verifyApprovalToken(body.approval_token, keys.publicKeyPem, body.request, undefined, {
      policy_id: decision.policy_ids[0],
      required_roles: decision.approval?.required_roles,
    });
    await auditLog.append({
      event_type: 'approval.verified',
      request_id: body.request.request_id,
      actor_id: claims.approved_by,
      agent_id: body.request.agent.agent_id,
      tool_name: body.request.tool.name,
      risk_level: claims.risk_level,
      policy_ids: [claims.policy_id],
      argument_hash: hashArguments(body.request.arguments),
      approval_id: claims.approval_id,
      result: 'success',
    });
    json(response, 200, { valid: true, claims });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/executions') {
    const body = await readJson<ExecutionInput>(request);
    validateToolCall(body.request);
    const execution = await executeGovernedToolCall({
      input: body,
      policyFile,
      auditLog,
      adapters,
      publicKeyPem: keys.publicKeyPem,
    });
    const status = execution.result.status === 'blocked' ? 403 : execution.result.status === 'failure' ? 502 : 200;
    json(response, status, execution);
    return;
  }

  json(response, 404, { error: 'not found' });
}

async function getPendingApproval(storage: Storage, approvalId: string): Promise<ApprovalRequestRecord> {
  const record = await storage.getApprovalRequest(approvalId);
  if (!record) throw new HttpError(404, `Approval request not found: ${approvalId}`);
  if (record.status !== 'pending') throw new HttpError(409, `Approval request ${approvalId} is already ${record.status}.`);
  return record;
}

function validateApprover(approvedBy: string | undefined, approvedRole: string | undefined, decision: DecisionResponse, auth: AuthContext): string | undefined {
  if (!approvedBy) throw new HttpError(400, 'approved_by is required.');
  validateAuthSubject(approvedBy, auth);
  const requiredRoles = decision.approval?.required_roles ?? [];
  if (requiredRoles.length === 0) return approvedRole;
  if (auth.key && auth.roles.length === 0) throw new HttpError(403, 'API key has no configured roles; approval-required policies fail closed.');
  if (!approvedRole) throw new HttpError(403, `Approval requires one of these roles: ${requiredRoles.join(', ')}.`);
  if (!requiredRoles.includes(approvedRole)) throw new HttpError(403, `Role ${approvedRole} is not authorized for policy ${decision.policy_ids[0] ?? 'manual'}.`);
  if (auth.roles.length > 0 && !auth.roles.includes(approvedRole)) throw new HttpError(403, `API key is not authorized for role ${approvedRole}.`);
  return approvedRole;
}

function validateAuthSubject(actor: string, auth: AuthContext): void {
  if (auth.subject && actor !== auth.subject) throw new HttpError(403, `API key is bound to ${auth.subject}, not ${actor}.`);
}

function resolveApprovalTtl(requestedTtlSeconds: number | undefined, decision: DecisionResponse): number {
  const policyMax = decision.approval?.token_ttl_seconds;
  try {
    return normalizeApprovalTtl(requestedTtlSeconds ?? policyMax, policyMax ?? MAX_APPROVAL_TTL_SECONDS);
  } catch (error) {
    throw new HttpError(400, error instanceof Error ? error.message : 'Invalid approval token TTL.');
  }
}

async function loadOrCreateKeys(privateKeyFile: string, publicKeyFile: string): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
  const [privateResult, publicResult] = await Promise.allSettled([readFile(privateKeyFile, 'utf8'), readFile(publicKeyFile, 'utf8')]);
  if (privateResult.status === 'fulfilled' && publicResult.status === 'fulfilled') {
    return { privateKeyPem: privateResult.value, publicKeyPem: publicResult.value };
  }
  const privateMissing = privateResult.status === 'rejected' && (privateResult.reason as NodeJS.ErrnoException).code === 'ENOENT';
  const publicMissing = publicResult.status === 'rejected' && (publicResult.reason as NodeJS.ErrnoException).code === 'ENOENT';
  if (privateMissing && publicMissing) {
    const keys = generateSigningKeyPair();
    await mkdir(dirname(privateKeyFile), { recursive: true });
    await Promise.all([writeFile(privateKeyFile, keys.privateKeyPem, { mode: 0o600 }), writeFile(publicKeyFile, keys.publicKeyPem, { mode: 0o644 })]);
    return keys;
  }
  if (privateMissing || publicMissing) {
    throw new Error('Partial approval signing key loss detected. Refusing to rotate keys automatically. Restore the missing key file or intentionally rotate both keys.');
  }
  if (privateResult.status === 'rejected') throw privateResult.reason;
  throw publicResult.status === 'rejected' ? publicResult.reason : new Error('Could not load approval signing keys.');
}

async function auditDecision(auditLog: AuditLog, toolCall: ToolCallRequest, decision: DecisionResponse): Promise<void> {
  await auditLog.append({
    event_type: 'decision.evaluated',
    request_id: toolCall.request_id,
    actor_id: toolCall.actor.user_id,
    agent_id: toolCall.agent.agent_id,
    tool_name: toolCall.tool.name,
    decision: decision.decision,
    risk_level: decision.risk_level,
    policy_ids: decision.policy_ids,
    argument_hash: decision.argument_hash,
  });
}

function getAuthContext(
  request: IncomingMessage,
  apiKeys: string[],
  apiKeyRoles: Record<string, string[]>,
  apiKeyIdentities: Record<string, string>,
): AuthContext {
  if (apiKeys.length === 0) return { authenticated: true, roles: [] };
  if (request.method === 'GET' && request.url?.startsWith('/healthz')) return { authenticated: true, roles: [] };
  const candidate = requestApiKey(request);
  if (!candidate || !apiKeys.includes(candidate)) return { authenticated: false, roles: [] };
  return { authenticated: true, key: candidate, subject: apiKeyIdentities[candidate], roles: apiKeyRoles[candidate] ?? [] };
}

function requestApiKey(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization ?? '';
  const bearer = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : undefined;
  const headerKey = request.headers['x-tanod-api-key'];
  return bearer ?? (Array.isArray(headerKey) ? headerKey[0] : headerKey);
}

function validateToolCall(value: ToolCallRequest): void {
  if (!value || typeof value !== 'object') throw new HttpError(400, 'request body must be an object');
  if (value.version !== 'v1') throw new HttpError(400, 'request.version must be v1');
  if (!value.request_id) throw new HttpError(400, 'request.request_id is required');
  if (!value.actor?.user_id) throw new HttpError(400, 'request.actor.user_id is required');
  if (!value.agent?.agent_id) throw new HttpError(400, 'request.agent.agent_id is required');
  if (!value.tool?.name) throw new HttpError(400, 'request.tool.name is required');
  if (!value.arguments || typeof value.arguments !== 'object') throw new HttpError(400, 'request.arguments object is required');
}

async function readJson<T>(request: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  try {
    for await (const chunk of request) {
      const buffer = Buffer.from(chunk);
      totalBytes += buffer.length;
      if (totalBytes > MAX_REQUEST_BODY_BYTES) throw new HttpError(413, `request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
      chunks.push(buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (error instanceof SyntaxError) throw new HttpError(400, 'request body must be valid JSON');
    throw error;
  }
}

function writeCorsHeaders(response: ServerResponse): void {
  response.setHeader('access-control-allow-origin', '*');
  response.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  response.setHeader('access-control-allow-headers', 'content-type,authorization,x-tanod-api-key');
}

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
