import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createAdapterRegistry, type ToolAdapter } from './adapters.js';
import { approvalConsoleHtml } from './console.js';
import { AuditLog } from './audit.js';
import { hashArguments } from './canonical.js';
import type { DecisionResponse, PolicyFile, ToolCallRequest } from './domain.js';
import { executeGovernedToolCall, type ExecutionInput } from './execution.js';
import { evaluatePolicy, loadPolicyFile } from './policy.js';
import { generateSigningKeyPair, signApproval, verifyApprovalToken } from './signing.js';
import { createStorageFromEnv, type ApprovalStatus, type Storage } from './storage.js';

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
  apiKeys: string[];
}

export async function startServer(config: ServerConfig): Promise<void> {
  const policyFile = await loadPolicyFile(config.policyFile);
  const storage = createStorageFromEnv(process.env);
  await storage.initialize();
  const auditLog = new AuditLog(config.auditFile, storage);
  const keys = await loadOrCreateKeys(config.privateKeyFile, config.publicKeyFile);
  const adapters = createAdapterRegistry({
    enableShellExecution: config.enableShellExecution,
    shellTimeoutMs: config.shellTimeoutMs,
    httpTimeoutMs: config.httpTimeoutMs,
  });

  const server = createServer(async (request, response) => {
    try {
      if (!isAuthorized(request, config.apiKeys)) {
        json(response, 401, { error: 'unauthorized' });
        return;
      }
      await route(request, response, policyFile, auditLog, keys, adapters, storage);
    } catch (error) {
      json(response, 500, { error: error instanceof Error ? error.message : 'unknown error' });
    }
  });

  await new Promise<void>((resolve) => server.listen(config.port, config.host, resolve));
  console.log(`tanod gateway listening on http://${config.host}:${config.port}`);
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  policyFile: PolicyFile,
  auditLog: AuditLog,
  keys: { privateKeyPem: string; publicKeyPem: string },
  adapters: Map<string, ToolAdapter>,
  storage: Storage,
): Promise<void> {
  const method = request.method ?? 'GET';
  const url = new URL(request.url ?? '/', 'http://localhost');

  if (method === 'GET' && url.pathname === '/healthz') {
    json(response, 200, { status: 'ok', service: 'tanod-gateway', adapters: [...adapters.keys()] });
    return;
  }

  if (method === 'GET' && url.pathname === '/console') {
    html(response, 200, approvalConsoleHtml());
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
    const { token, claims } = signApproval(
      {
        request: body.request,
        approved_by: body.approved_by,
        approved_role: body.approved_role,
        policy_id: body.policy_id ?? decision.policy_ids[0] ?? 'manual',
        risk_level: decision.risk_level,
        ttl_seconds: body.ttl_seconds,
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
      details: { approved_role: body.approved_role, expires_at: new Date(claims.exp * 1000).toISOString() },
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
    const record = await storage.getApprovalRequest(approvalId);
    if (!record) {
      json(response, 404, { error: `Approval request not found: ${approvalId}` });
      return;
    }
    if (record.status !== 'pending') {
      json(response, 409, { error: `Approval request ${approvalId} is already ${record.status}.`, approval_request: record });
      return;
    }
    const { token, claims } = signApproval(
      {
        request: record.request,
        approved_by: body.approved_by,
        approved_role: body.approved_role,
        policy_id: record.decision.policy_ids[0] ?? 'manual',
        risk_level: record.decision.risk_level,
        ttl_seconds: body.ttl_seconds,
        approval_id: record.approval_id,
      },
      keys.privateKeyPem,
    );
    const updated = await storage.approveApprovalRequest(approvalId, {
      approved_by: body.approved_by,
      approved_role: body.approved_role,
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
      details: { approved_role: body.approved_role, expires_at: updated.expires_at },
    });
    json(response, 200, updated);
    return;
  }

  const approvalRejectMatch = method === 'POST' ? url.pathname.match(/^\/v1\/approval-requests\/([^/]+)\/reject$/) : null;
  if (approvalRejectMatch) {
    const approvalId = decodeURIComponent(approvalRejectMatch[1]);
    const body = await readJson<{ rejected_by: string; reason?: string }>(request);
    const record = await storage.getApprovalRequest(approvalId);
    if (!record) {
      json(response, 404, { error: `Approval request not found: ${approvalId}` });
      return;
    }
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
    const claims = verifyApprovalToken(body.approval_token, keys.publicKeyPem, body.request);
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

async function loadOrCreateKeys(privateKeyFile: string, publicKeyFile: string): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
  try {
    const [privateKeyPem, publicKeyPem] = await Promise.all([readFile(privateKeyFile, 'utf8'), readFile(publicKeyFile, 'utf8')]);
    return { privateKeyPem, publicKeyPem };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const keys = generateSigningKeyPair();
    await mkdir(dirname(privateKeyFile), { recursive: true });
    await Promise.all([writeFile(privateKeyFile, keys.privateKeyPem, { mode: 0o600 }), writeFile(publicKeyFile, keys.publicKeyPem, { mode: 0o644 })]);
    return keys;
  }
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

function isAuthorized(request: IncomingMessage, apiKeys: string[]): boolean {
  if (apiKeys.length === 0) return true;
  if (request.method === 'GET' && request.url?.startsWith('/healthz')) return true;
  if (request.method === 'GET' && request.url?.startsWith('/console')) return true;
  const authorization = request.headers.authorization ?? '';
  const bearer = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : undefined;
  const headerKey = request.headers['x-tanod-api-key'];
  const candidate = bearer ?? (Array.isArray(headerKey) ? headerKey[0] : headerKey);
  return typeof candidate === 'string' && apiKeys.includes(candidate);
}

function validateToolCall(value: ToolCallRequest): void {
  if (value.version !== 'v1') throw new Error('request.version must be v1');
  if (!value.request_id) throw new Error('request.request_id is required');
  if (!value.actor?.user_id) throw new Error('request.actor.user_id is required');
  if (!value.agent?.agent_id) throw new Error('request.agent.agent_id is required');
  if (!value.tool?.name) throw new Error('request.tool.name is required');
  if (!value.arguments || typeof value.arguments !== 'object') throw new Error('request.arguments object is required');
}

async function readJson<T>(request: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T;
}

function html(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, { 'content-type': 'text/html; charset=utf-8' });
  response.end(body);
}

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
