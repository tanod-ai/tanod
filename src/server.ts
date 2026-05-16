import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createAdapterRegistry, type ToolAdapter } from './adapters.js';
import { AuditLog } from './audit.js';
import { hashArguments } from './canonical.js';
import type { Decision, DecisionResponse, PolicyFile, ToolCallRequest } from './domain.js';
import { executeGovernedToolCall, type ExecutionInput } from './execution.js';
import { evaluatePolicy, loadPolicyFile, validatePolicyFile } from './policy.js';
import { MAX_APPROVAL_TTL_SECONDS, generateSigningKeyPair, normalizeApprovalTtl, signApproval, verifyApprovalToken } from './signing.js';
import { createStorageFromEnv, type ApprovalRequestRecord, type ApprovalStatus, type Storage, type ToolCallRecord, type UserRecord, type UserRole } from './storage.js';
import { verifyOidcToken, type OidcProviderConfig } from './oidc.js';
import { routeCoreApi } from './core-api.js';
import { isServerApiRequest, routeServerApi, routeServerAuthenticatedApi } from './server-api.js';

const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const RBAC_ROLES: UserRole[] = ['Admin', 'Approver', 'Viewer'];

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
  allowUnauthenticated?: boolean;
  apiKeyRoles?: Record<string, string[]>;
  apiKeyIdentities?: Record<string, string>;
  oidcProviders?: OidcProviderConfig[];
  oauth2Providers?: OAuth2ProviderConfig[];
  oauth2CallbackBaseUrl?: string;
  oidcIdentityRoles?: Record<string, string[]>;
  bootstrapAdmins?: string[];
  consoleBaseUrl?: string;
  consoleApiBaseUrl?: string;
  invitationTtlDays?: number;
  invitationEmailWebhook?: string;
}

interface AuthContext {
  authenticated: boolean;
  scheme: 'none' | 'api_key' | 'oidc' | 'oauth2';
  key?: string;
  subject?: string;
  roles: string[];
  user?: UserRecord;
  rbacRoles: UserRole[];
}

interface OAuth2ProviderConfig {
  id: string;
  label?: string;
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userUrl: string;
  emailsUrl?: string;
  scope?: string;
}

interface OAuthSessionClaims {
  provider: string;
  identity: string;
  exp: number;
}

interface AgentSummary {
  agent_id: string;
  agent_type?: string;
  environment?: string;
  tool_call_count: number;
  pending_approval_count: number;
  approved_approval_count: number;
  rejected_approval_count: number;
  decisions: Partial<Record<Decision, number>>;
  tools: string[];
  actors: string[];
  last_seen_at?: string;
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
  const policyRef = { value: await loadPolicyFile(config.policyFile) };
  const storage = createStorageFromEnv(process.env);
  await storage.initialize();
  for (const identity of config.bootstrapAdmins ?? []) {
    await storage.upsertUser({ identity, roles: ['Admin'], status: 'active' });
  }
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
      const corsAllowed = writeCorsHeaders(request, response, config);
      if (request.method === 'OPTIONS') {
        response.writeHead(corsAllowed ? 204 : 403);
        response.end();
        return;
      }
      if (isServerApiRequest(request)) {
        await routeServerApi(request, response, {
          consoleApiBaseUrl: config.consoleApiBaseUrl,
          consoleBaseUrl: config.consoleBaseUrl,
          oidcProviders: config.oidcProviders ?? [],
          oauth2Providers: config.oauth2Providers ?? [],
          oauthSessionSecret: keys.privateKeyPem,
          oauth2CallbackBaseUrl: config.oauth2CallbackBaseUrl,
          storage,
        });
        return;
      }
      const auth = await getAuthContext(request, {
        apiKeys: config.apiKeys,
        allowUnauthenticated: config.allowUnauthenticated === true,
        apiKeyRoles: config.apiKeyRoles ?? {},
        apiKeyIdentities: config.apiKeyIdentities ?? {},
        oidcProviders: config.oidcProviders ?? [],
        oauth2Providers: config.oauth2Providers ?? [],
        oauthSessionSecret: keys.privateKeyPem,
        oidcIdentityRoles: config.oidcIdentityRoles ?? {},
        bootstrapAdmins: config.bootstrapAdmins ?? [],
        storage,
      });
      if (!auth.authenticated) {
        json(response, 401, { error: 'unauthorized' });
        return;
      }
      const sharedHandler = () => route(request, response, policyRef, auditLog, keys, adapters, storage, auth, config);
      if (auth.scheme === 'oidc' || auth.scheme === 'oauth2') {
        await routeServerAuthenticatedApi(request, response, sharedHandler);
        return;
      }
      await routeCoreApi(request, response, sharedHandler);
    } catch (error) {
      const statusCode = error instanceof HttpError ? error.statusCode : hasStatusCode(error) ? error.statusCode : error instanceof SyntaxError ? 400 : 500;
      json(response, statusCode, { error: error instanceof Error ? error.message : 'unknown error' });
    }
  });

  await new Promise<void>((resolve) => server.listen(config.port, config.host, resolve));
  console.log(`tanod gateway listening on http://${config.host}:${config.port}`);
  return server;
}

function hasStatusCode(error: unknown): error is { statusCode: number } {
  return typeof error === 'object' && error !== null && typeof (error as { statusCode?: unknown }).statusCode === 'number';
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  policyRef: { value: PolicyFile },
  auditLog: AuditLog,
  keys: { privateKeyPem: string; publicKeyPem: string },
  adapters: Map<string, ToolAdapter>,
  storage: Storage,
  auth: AuthContext,
  config: ServerConfig,
): Promise<void> {
  const method = request.method ?? 'GET';
  const url = new URL(request.url ?? '/', 'http://localhost');
  const policyFile = policyRef.value;

  if (method === 'GET' && url.pathname === '/healthz') {
    json(response, 200, { status: 'ok', service: 'tanod-gateway', adapters: [...adapters.keys()] });
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/me') {
    json(response, 200, {
      identity: auth.subject,
      role: highestRole(auth.rbacRoles),
      roles: auth.rbacRoles,
      external_roles: auth.roles,
      user: auth.user,
      capabilities: capabilitiesFor(auth),
    });
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/users') {
    requireRole(auth, 'Admin');
    json(response, 200, { users: await storage.listUsers() });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/users') {
    requireRole(auth, 'Admin');
    const body = await readJson<{ identity?: string; user_id?: string; display_name?: string; displayName?: string; role?: UserRole; roles?: UserRole[]; status?: 'active' | 'disabled' }>(request);
    const identity = requireNonEmpty(body.identity ?? body.user_id, 'user_id');
    const user = await storage.upsertUser({
      identity,
      displayName: requireNonEmpty(body.display_name ?? body.displayName ?? identity, 'display_name'),
      roles: validateUserRoles(body.roles ?? (body.role ? [body.role] : undefined)),
      status: body.status ?? 'active',
    });
    await auditLog.append({ event_type: 'user.upserted', actor_id: auth.subject, result: 'success', details: { identity: user.identity, display_name: user.display_name, roles: user.roles, status: user.status } });
    json(response, 200, user);
    return;
  }

  const userMatch = url.pathname.match(/^\/v1\/users\/([^/]+)$/);
  if (userMatch && method === 'PATCH') {
    requireRole(auth, 'Admin');
    const body = await readJson<{ display_name?: string; displayName?: string; role?: UserRole; roles?: UserRole[]; status?: 'active' | 'disabled' }>(request);
    const user = await storage.updateUser(decodeURIComponent(userMatch[1]), {
      displayName: body.display_name ?? body.displayName,
      roles: body.roles || body.role ? validateUserRoles(body.roles ?? (body.role ? [body.role] : undefined)) : undefined,
      status: body.status,
    });
    await auditLog.append({ event_type: 'user.updated', actor_id: auth.subject, result: 'success', details: { identity: user.identity, display_name: user.display_name, roles: user.roles, status: user.status } });
    json(response, 200, user);
    return;
  }

  if (userMatch && method === 'DELETE') {
    requireRole(auth, 'Admin');
    await storage.deleteUser(decodeURIComponent(userMatch[1]));
    await auditLog.append({ event_type: 'user.deleted', actor_id: auth.subject, result: 'success', details: { user_id: decodeURIComponent(userMatch[1]) } });
    json(response, 200, { deleted: true });
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/invitations') {
    requireRole(auth, 'Admin');
    json(response, 200, { invitations: await storage.listInvitations() });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/invitations') {
    requireRole(auth, 'Admin');
    const body = await readJson<{ invites: Array<{ email: string; role?: UserRole; roles?: UserRole[] }> }>(request);
    const baseUrl = (config.consoleBaseUrl ?? '').replace(/\/$/, '');
    const expiresAt = new Date(Date.now() + (config.invitationTtlDays ?? 7) * 24 * 60 * 60 * 1000).toISOString();
    const invitations = [];
    for (const invite of body.invites ?? []) {
      const invitation = await storage.createInvitation({
        email: requireNonEmpty(invite.email, 'email'),
        roles: validateUserRoles(invite.roles ?? (invite.role ? [invite.role] : undefined)),
        invited_by: auth.subject ?? 'unknown',
        expires_at: expiresAt,
      });
      const inviteUrl = baseUrl ? `${baseUrl}/?invite=${encodeURIComponent(invitation.token)}` : `/?invite=${encodeURIComponent(invitation.token)}`;
      await sendInvitationEmail(config, invitation.email, invitation.roles, inviteUrl);
      invitations.push({ ...invitation, invite_url: inviteUrl });
    }
    await auditLog.append({ event_type: 'invitation.created', actor_id: auth.subject, result: 'success', details: { count: invitations.length } });
    json(response, 202, { invitations });
    return;
  }

  const invitationAcceptMatch = method === 'POST' ? url.pathname.match(/^\/v1\/invitations\/([^/]+)\/accept$/) : null;
  if (invitationAcceptMatch) {
    if (!auth.subject) throw new HttpError(401, 'authenticated identity required to accept invitation.');
    const user = await storage.acceptInvitation(decodeURIComponent(invitationAcceptMatch[1]), auth.subject);
    await auditLog.append({ event_type: 'invitation.accepted', actor_id: auth.subject, result: 'success', details: { roles: user.roles } });
    json(response, 200, user);
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/policies') {
    requireRole(auth, 'Viewer');
    json(response, 200, {
      version: policyFile.version,
      default_decision: policyFile.default_decision,
      default_risk_level: policyFile.default_risk_level,
      policies: policyFile.policies,
    });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/policies') {
    requireRole(auth, 'Admin');
    const body = await readJson<PolicyFile>(request);
    validatePolicyFile(body);
    policyRef.value = body;
    await writePolicyFile(config.policyFile, body);
    await auditLog.append({ event_type: 'policy.replaced', actor_id: auth.subject, result: 'success', details: { count: body.policies.length } });
    json(response, 200, policyRef.value);
    return;
  }

  const policyMatch = url.pathname.match(/^\/v1\/policies\/([^/]+)$/);
  if (policyMatch && method === 'PUT') {
    requireRole(auth, 'Admin');
    const policyId = decodeURIComponent(policyMatch[1]);
    const body = await readJson<PolicyFile['policies'][number]>(request);
    if (body.id !== policyId) throw new HttpError(400, 'policy id in path and body must match.');
    const next: PolicyFile = { ...policyRef.value, policies: upsertPolicy(policyRef.value.policies, body) };
    validatePolicyFile(next);
    policyRef.value = next;
    await writePolicyFile(config.policyFile, next);
    await auditLog.append({ event_type: 'policy.updated', actor_id: auth.subject, result: 'success', details: { policy_id: policyId } });
    json(response, 200, body);
    return;
  }

  if (policyMatch && method === 'DELETE') {
    requireRole(auth, 'Admin');
    const policyId = decodeURIComponent(policyMatch[1]);
    const next: PolicyFile = { ...policyRef.value, policies: policyRef.value.policies.filter((policy) => policy.id !== policyId) };
    validatePolicyFile(next);
    policyRef.value = next;
    await writePolicyFile(config.policyFile, next);
    await auditLog.append({ event_type: 'policy.deleted', actor_id: auth.subject, result: 'success', details: { policy_id: policyId } });
    json(response, 200, { deleted: true });
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/audit-events') {
    requireRole(auth, 'Viewer');
    const limitParam = url.searchParams.get('limit');
    const limit = limitParam ? Number(limitParam) : undefined;
    const events = await auditLog.listEvents({
      event_type: url.searchParams.get('event_type') ?? undefined,
      request_id: url.searchParams.get('request_id') ?? undefined,
      limit,
    });
    json(response, 200, { audit_events: events });
    return;
  }

  if (method === 'GET' && url.pathname === '/v1/agents') {
    requireRole(auth, 'Viewer');
    const [toolCalls, approvals] = await Promise.all([storage.listToolCalls(), storage.listApprovalRequests()]);
    json(response, 200, { agents: summarizeAgents(toolCalls, approvals) });
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
    requireRole(auth, 'Viewer');
    const status = url.searchParams.get('status') as ApprovalStatus | null;
    const records = await storage.listApprovalRequests(status ?? undefined);
    json(response, 200, { approval_requests: records });
    return;
  }

  const approvalGetMatch = method === 'GET' ? url.pathname.match(/^\/v1\/approval-requests\/([^/]+)$/) : null;
  if (approvalGetMatch) {
    requireRole(auth, 'Viewer');
    const approvalId = decodeURIComponent(approvalGetMatch[1]);
    const record = await storage.getApprovalRequest(approvalId);
    if (!record) throw new HttpError(404, `Approval request not found: ${approvalId}`);
    json(response, 200, record);
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

function signEnvelope(prefix: string, payload: Record<string, unknown>, secret: string): string {
  const encoded = base64urlEncode(JSON.stringify(payload));
  const signature = hmac(encoded, secret);
  return `${prefix}.${encoded}.${signature}`;
}

function verifyEnvelope<T>(prefix: string, token: string, secret: string): T {
  const [actualPrefix, encoded, signature] = token.split('.');
  if (actualPrefix !== prefix || !encoded || !signature) throw new HttpError(400, 'Invalid signed token.');
  const expected = hmac(encoded, secret);
  if (!constantTimeEqual(signature, expected)) throw new HttpError(400, 'Invalid signed token signature.');
  return JSON.parse(Buffer.from(base64urlToBase64(encoded), 'base64').toString('utf8')) as T;
}

function hmac(value: string, secret: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function base64urlEncode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function base64urlToBase64(value: string): string {
  return value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(302, { location });
  response.end();
}

function summarizeAgents(toolCalls: ToolCallRecord[], approvals: ApprovalRequestRecord[]): AgentSummary[] {
  const summaries = new Map<string, AgentSummary & { toolsSet: Set<string>; actorsSet: Set<string>; requestIds: Set<string> }>();

  for (const toolCall of toolCalls) {
    const summary = ensureAgentSummary(summaries, toolCall.request);
    if (!summary.requestIds.has(toolCall.request_id)) {
      summary.requestIds.add(toolCall.request_id);
      summary.tool_call_count += 1;
    }
    summary.decisions[toolCall.decision.decision] = (summary.decisions[toolCall.decision.decision] ?? 0) + 1;
    summary.toolsSet.add(toolCall.request.tool.name);
    summary.actorsSet.add(toolCall.request.actor.user_id);
    summary.last_seen_at = maxIso(summary.last_seen_at, toolCall.created_at);
  }

  for (const approval of approvals) {
    const summary = ensureAgentSummary(summaries, approval.request);
    if (!summary.requestIds.has(approval.request_id)) {
      summary.requestIds.add(approval.request_id);
      summary.tool_call_count += 1;
      summary.decisions[approval.decision.decision] = (summary.decisions[approval.decision.decision] ?? 0) + 1;
    }
    if (approval.status === 'pending') summary.pending_approval_count += 1;
    if (approval.status === 'approved') summary.approved_approval_count += 1;
    if (approval.status === 'rejected') summary.rejected_approval_count += 1;
    summary.toolsSet.add(approval.request.tool.name);
    summary.actorsSet.add(approval.request.actor.user_id);
    summary.last_seen_at = maxIso(summary.last_seen_at, approval.updated_at);
  }

  return [...summaries.values()]
    .map(({ toolsSet, actorsSet, requestIds, ...summary }) => ({
      ...summary,
      tools: [...toolsSet].sort(),
      actors: [...actorsSet].sort(),
    }))
    .sort((a, b) => (b.last_seen_at ?? '').localeCompare(a.last_seen_at ?? ''));
}

function ensureAgentSummary(
  summaries: Map<string, AgentSummary & { toolsSet: Set<string>; actorsSet: Set<string>; requestIds: Set<string> }>,
  request: ToolCallRequest,
): AgentSummary & { toolsSet: Set<string>; actorsSet: Set<string>; requestIds: Set<string> } {
  const existing = summaries.get(request.agent.agent_id);
  if (existing) return existing;
  const created: AgentSummary & { toolsSet: Set<string>; actorsSet: Set<string>; requestIds: Set<string> } = {
    agent_id: request.agent.agent_id,
    agent_type: request.agent.agent_type,
    environment: request.agent.environment,
    tool_call_count: 0,
    pending_approval_count: 0,
    approved_approval_count: 0,
    rejected_approval_count: 0,
    decisions: {},
    tools: [],
    actors: [],
    toolsSet: new Set(),
    actorsSet: new Set(),
    requestIds: new Set(),
  };
  summaries.set(created.agent_id, created);
  return created;
}

function maxIso(current: string | undefined, candidate: string | undefined): string | undefined {
  if (!candidate) return current;
  if (!current) return candidate;
  return candidate > current ? candidate : current;
}

function requireRole(auth: AuthContext, role: UserRole): void {
  if (role === 'Admin' && !hasRbacRole(auth, 'Admin')) throw new HttpError(403, 'Admin role required.');
  if (role === 'Approver' && !canApprove(auth)) throw new HttpError(403, 'Approver or Admin role required.');
  if (role === 'Viewer' && auth.rbacRoles.length === 0 && auth.scheme !== 'none') throw new HttpError(403, 'Viewer, Approver, or Admin role required.');
}

function canApprove(auth: AuthContext): boolean {
  return hasRbacRole(auth, 'Admin') || hasRbacRole(auth, 'Approver');
}

function hasRbacRole(auth: AuthContext, role: UserRole): boolean {
  return auth.rbacRoles.includes(role);
}

function capabilitiesFor(auth: AuthContext): Record<string, boolean> {
  return {
    view: Boolean(auth.authenticated),
    approve: canApprove(auth),
    administer: hasRbacRole(auth, 'Admin'),
    mutate_policies: hasRbacRole(auth, 'Admin'),
  };
}

function validateUserRoles(roles: UserRole[] | undefined): UserRole[] {
  const unique = [...new Set(roles ?? [])];
  if (unique.length === 0) throw new HttpError(400, 'at least one role is required.');
  for (const role of unique) {
    if (!RBAC_ROLES.includes(role)) throw new HttpError(400, `roles must contain only: ${RBAC_ROLES.join(', ')}`);
  }
  return unique;
}

function requireNonEmpty(value: string | undefined, field: string): string {
  if (!value?.trim()) throw new HttpError(400, `${field} is required.`);
  return value.trim();
}

function upsertPolicy(policies: PolicyFile['policies'], policy: PolicyFile['policies'][number]): PolicyFile['policies'] {
  const index = policies.findIndex((candidate) => candidate.id === policy.id);
  if (index === -1) return [...policies, policy];
  return policies.map((candidate, candidateIndex) => (candidateIndex === index ? policy : candidate));
}

function validateApprover(approvedBy: string | undefined, approvedRole: string | undefined, decision: DecisionResponse, auth: AuthContext): string | undefined {
  if (!approvedBy) throw new HttpError(400, 'approved_by is required.');
  validateAuthSubject(approvedBy, auth);
  if (!canApprove(auth)) throw new HttpError(403, 'Approver or Admin role required.');
  const requiredRoles = decision.approval?.required_roles ?? [];
  if (requiredRoles.length === 0) return approvedRole ?? highestRole(auth.rbacRoles);
  const effectiveRole = approvedRole ?? firstGrantedRole(auth.roles, requiredRoles);
  if (auth.scheme !== 'none' && auth.roles.length === 0) throw new HttpError(403, 'Authenticated approver has no configured roles; approval-required policies fail closed.');
  if (!effectiveRole) throw new HttpError(403, `Approval requires one of these roles: ${requiredRoles.join(', ')}.`);
  if (!requiredRoles.includes(effectiveRole)) throw new HttpError(403, `Role ${effectiveRole} is not authorized for policy ${decision.policy_ids[0] ?? 'manual'}.`);
  if (!auth.roles.includes(effectiveRole)) throw new HttpError(403, `Authenticated identity is not authorized for role ${effectiveRole}.`);
  return effectiveRole;
}

function firstGrantedRole(grantedRoles: string[], requiredRoles: string[]): string | undefined {
  return requiredRoles.find((role) => grantedRoles.includes(role));
}

function validateAuthSubject(actor: string, auth: AuthContext): void {
  if (auth.subject && actor !== auth.subject) throw new HttpError(403, `Authenticated identity is ${auth.subject}, not ${actor}.`);
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

async function writePolicyFile(path: string, policyFile: PolicyFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(policyFile, null, 2)}\n`, 'utf8');
}

async function sendInvitationEmail(config: ServerConfig, email: string, roles: UserRole[], inviteUrl: string): Promise<void> {
  if (!config.invitationEmailWebhook) return;
  const response = await fetch(config.invitationEmailWebhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      to: email,
      subject: 'Your tanod invitation',
      text: `You have been invited to tanod with these roles: ${roles.join(', ')}. Use this link to accept: ${inviteUrl}`,
      invite_url: inviteUrl,
      roles,
    }),
  });
  if (!response.ok) throw new HttpError(502, `Invitation email webhook failed: ${response.statusText}`);
}

async function getAuthContext(
  request: IncomingMessage,
  config: {
    apiKeys: string[];
    allowUnauthenticated: boolean;
    apiKeyRoles: Record<string, string[]>;
    apiKeyIdentities: Record<string, string>;
    oidcProviders: OidcProviderConfig[];
    oauth2Providers: OAuth2ProviderConfig[];
    oauthSessionSecret: string;
    oidcIdentityRoles: Record<string, string[]>;
    bootstrapAdmins: string[];
    storage: Storage;
  },
): Promise<AuthContext> {
  if (config.allowUnauthenticated) return { authenticated: true, scheme: 'none', subject: 'development-admin', roles: ['Admin'], rbacRoles: ['Admin'] };
  const hasConfiguredAuth = config.apiKeys.length > 0 || config.oidcProviders.length > 0 || config.oauth2Providers.length > 0;
  if (!hasConfiguredAuth) return { authenticated: true, scheme: 'none', subject: 'development-admin', roles: ['Admin'], rbacRoles: ['Admin'] };
  if (request.method === 'GET' && request.url?.startsWith('/healthz')) return { authenticated: true, scheme: 'none', roles: [], rbacRoles: [] };

  const apiKey = requestApiKey(request);
  if (apiKey && config.apiKeys.includes(apiKey)) {
    const roles = config.apiKeyRoles[apiKey] ?? [];
    const rbacRoles = rbacRolesFrom(roles);
    return {
      authenticated: true,
      scheme: 'api_key',
      key: apiKey,
      subject: config.apiKeyIdentities[apiKey],
      roles,
      rbacRoles,
    };
  }

  const token = requestBearerToken(request) ?? requestCookie(request, 'tanod_session');
  if (token?.startsWith('tanod-oauth-session.')) {
    const session = verifyEnvelope<OAuthSessionClaims>('tanod-oauth-session', token, config.oauthSessionSecret);
    if (session.exp < Math.floor(Date.now() / 1000)) return { authenticated: false, scheme: 'none', roles: [], rbacRoles: [] };
    const roles = config.oidcIdentityRoles[session.identity] ?? [];
    const user = await config.storage.getUserByIdentity(session.identity);
    if (!user || user.status !== 'active') return { authenticated: false, scheme: 'none', roles: [], rbacRoles: [] };
    return {
      authenticated: true,
      scheme: 'oauth2',
      subject: session.identity,
      roles,
      user,
      rbacRoles: user.roles,
    };
  }

  if (token && config.oidcProviders.length > 0) {
    const identity = await verifyOidcToken(token, config.oidcProviders);
    if (identity) {
      const roles = [...new Set([...identity.roles, ...(config.oidcIdentityRoles[identity.subject] ?? [])])];
      const user = await config.storage.getUserByIdentity(identity.subject);
      if (!user || user.status !== 'active') return { authenticated: false, scheme: 'none', roles: [], rbacRoles: [] };
      return {
        authenticated: true,
        scheme: 'oidc',
        subject: identity.subject,
        roles,
        user,
        rbacRoles: user.roles,
      };
    }
  }

  return { authenticated: false, scheme: 'none', roles: [], rbacRoles: [] };
}

function providerLabel(id: string): string {
  if (id === 'github') return 'GitHub';
  if (id === 'google') return 'Google';
  if (id === 'microsoft') return 'Microsoft Entra ID';
  return id.replace(/[-_]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function requestApiBaseUrl(request: IncomingMessage): string {
  const host = request.headers.host ?? '127.0.0.1:8787';
  const protoHeader = request.headers['x-forwarded-proto'];
  const proto = Array.isArray(protoHeader) ? protoHeader[0] : protoHeader;
  return `${proto || 'http'}://${host}`;
}

function rbacRolesFrom(roles: string[]): UserRole[] {
  return roles.filter((role): role is UserRole => role === 'Admin' || role === 'Approver' || role === 'Viewer');
}

function highestRole(roles: UserRole[]): UserRole | undefined {
  if (roles.includes('Admin')) return 'Admin';
  if (roles.includes('Approver')) return 'Approver';
  if (roles.includes('Viewer')) return 'Viewer';
  return undefined;
}

function requestApiKey(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization ?? '';
  const bearer = requestBearerToken(request);
  const headerKey = request.headers['x-tanod-api-key'];
  return bearer ?? (Array.isArray(headerKey) ? headerKey[0] : headerKey);
}

function requestBearerToken(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization ?? '';
  return authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : undefined;
}

function requestCookie(request: IncomingMessage, name: string): string | undefined {
  const cookieHeader = request.headers.cookie;
  const cookie = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader;
  if (!cookie) return undefined;
  for (const part of cookie.split(';')) {
    const [rawKey, ...rawValue] = part.trim().split('=');
    if (rawKey === name) return decodeURIComponent(rawValue.join('='));
  }
  return undefined;
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

function writeCorsHeaders(request: IncomingMessage, response: ServerResponse, config: ServerConfig): boolean {
  const origin = request.headers.origin;
  if (typeof origin !== 'string') {
    response.setHeader('access-control-allow-origin', '*');
  } else if (allowedCorsOrigins(request, config).has(origin)) {
    response.setHeader('access-control-allow-origin', origin);
    response.setHeader('vary', 'origin');
    response.setHeader('access-control-allow-credentials', 'true');
  } else {
    response.setHeader('vary', 'origin');
  }
  response.setHeader('access-control-allow-methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  response.setHeader('access-control-allow-headers', 'content-type,authorization,x-tanod-api-key');
  return typeof origin !== 'string' || allowedCorsOrigins(request, config).has(origin);
}

function allowedCorsOrigins(request: IncomingMessage, config: ServerConfig): Set<string> {
  const origins = new Set<string>([new URL(requestApiBaseUrl(request)).origin]);
  for (const value of [config.consoleBaseUrl, config.consoleApiBaseUrl]) {
    if (!value) continue;
    try {
      origins.add(new URL(value).origin);
    } catch {
      continue;
    }
  }
  return origins;
}

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
