import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { AuditLog } from './audit.js';
import { hashArguments } from './canonical.js';
import type { DecisionResponse, PolicyFile, ToolCallRequest } from './domain.js';
import { evaluatePolicy, loadPolicyFile } from './policy.js';
import { generateSigningKeyPair, signApproval, verifyApprovalToken } from './signing.js';

export interface ServerConfig {
  host: string;
  port: number;
  policyFile: string;
  auditFile: string;
  privateKeyFile: string;
  publicKeyFile: string;
}

export async function startServer(config: ServerConfig): Promise<void> {
  const policyFile = await loadPolicyFile(config.policyFile);
  const auditLog = new AuditLog(config.auditFile);
  const keys = await loadOrCreateKeys(config.privateKeyFile, config.publicKeyFile);

  const server = createServer(async (request, response) => {
    try {
      await route(request, response, policyFile, auditLog, keys);
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
): Promise<void> {
  const method = request.method ?? 'GET';
  const url = new URL(request.url ?? '/', 'http://localhost');

  if (method === 'GET' && url.pathname === '/healthz') {
    json(response, 200, { status: 'ok', service: 'tanod-gateway' });
    return;
  }

  if (method === 'POST' && url.pathname === '/v1/decisions') {
    const toolCall = await readJson<ToolCallRequest>(request);
    validateToolCall(toolCall);
    const decision = evaluatePolicy(policyFile, toolCall);
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

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
