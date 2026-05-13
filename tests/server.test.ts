import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import { startServer, type ServerConfig } from '../src/server.js';
import type { ToolCallRequest } from '../src/domain.js';

async function requestFixture(path: string): Promise<ToolCallRequest> {
  return JSON.parse(await readFile(path, 'utf8')) as ToolCallRequest;
}

async function withServer(t: import('node:test').TestContext, overrides: Partial<ServerConfig> = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-server-'));
  const config: ServerConfig = {
    host: '127.0.0.1',
    port: 0,
    policyFile: 'examples/policies/default.json',
    auditFile: join(dir, 'audit.jsonl'),
    privateKeyFile: join(dir, 'private.pem'),
    publicKeyFile: join(dir, 'public.pem'),
    enableShellExecution: false,
    shellTimeoutMs: 1000,
    httpTimeoutMs: 1000,
    apiKeys: ['dev-key'],
    apiKeyRoles: { 'dev-key': ['platform_owner'] },
    apiKeyIdentities: { 'dev-key': 'ross@example.com' },
    ...overrides,
  };
  const server = await startServer(config);
  t.after(() => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function post(base: string, path: string, body: unknown, apiKey = 'dev-key') {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

test('server maps malformed JSON and invalid requests to 4xx', async (t) => {
  const base = await withServer(t);
  const malformed = await post(base, '/v1/decisions', '{not json');
  assert.equal(malformed.status, 400);
  const invalid = await post(base, '/v1/decisions', { version: 'v1' });
  assert.equal(invalid.status, 400);
});

test('server rejects oversized request bodies', async (t) => {
  const base = await withServer(t);
  const response = await post(base, '/v1/decisions', `{"x":"${'a'.repeat(1024 * 1024 + 1)}"}`);
  assert.equal(response.status, 413);
});

test('approval endpoints enforce policy required roles and API key roles', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  assert.equal(createdResponse.status, 202);
  const created = await createdResponse.json() as { approval_id: string };

  const missingRole = await post(base, `/v1/approval-requests/${created.approval_id}/approve`, { approved_by: 'ross@example.com' });
  assert.equal(missingRole.status, 403);

  const wrongRole = await post(base, `/v1/approval-requests/${created.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'viewer' });
  assert.equal(wrongRole.status, 403);

  const approved = await post(base, `/v1/approval-requests/${created.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'platform_owner' });
  assert.equal(approved.status, 200);
});

test('approval endpoint rejects roles not granted to the API key', async (t) => {
  const base = await withServer(t, { apiKeys: ['limited-key'], apiKeyRoles: { 'limited-key': ['viewer'] } });
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' }, 'limited-key');
  assert.equal(createdResponse.status, 202);
  const created = await createdResponse.json() as { approval_id: string };

  const response = await post(
    base,
    `/v1/approval-requests/${created.approval_id}/approve`,
    { approved_by: 'ross@example.com', approved_role: 'platform_owner' },
    'limited-key',
  );
  assert.equal(response.status, 403);
});





test('approval endpoint fails closed when API key has no configured roles', async (t) => {
  const base = await withServer(t, { apiKeys: ['noroles-key'], apiKeyRoles: {}, apiKeyIdentities: { 'noroles-key': 'ross@example.com' } });
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' }, 'noroles-key');
  assert.equal(createdResponse.status, 202);
  const created = await createdResponse.json() as { approval_id: string };

  const response = await post(
    base,
    `/v1/approval-requests/${created.approval_id}/approve`,
    { approved_by: 'ross@example.com', approved_role: 'platform_owner' },
    'noroles-key',
  );
  assert.equal(response.status, 403);
});

test('approval endpoints enforce API-key-bound approver identity', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  const created = await createdResponse.json() as { approval_id: string };

  const response = await post(base, `/v1/approval-requests/${created.approval_id}/approve`, {
    approved_by: 'mallory@example.com',
    approved_role: 'platform_owner',
  });
  assert.equal(response.status, 403);
});

test('direct approval signing derives policy id and caps TTL from policy', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');

  const tooLong = await post(base, '/v1/approvals', {
    request: toolCall,
    approved_by: 'ross@example.com',
    approved_role: 'platform_owner',
    ttl_seconds: 901,
  });
  assert.equal(tooLong.status, 400);

  const response = await post(base, '/v1/approvals', {
    request: toolCall,
    approved_by: 'ross@example.com',
    approved_role: 'platform_owner',
    policy_id: 'client-supplied-policy-id',
  });
  assert.equal(response.status, 200);
  const signed = await response.json() as { approval_token: string };
  const verification = await post(base, '/v1/approval-verifications', { request: toolCall, approval_token: signed.approval_token });
  assert.equal(verification.status, 200);
  const verified = await verification.json() as { claims: { policy_id: string } };
  assert.equal(verified.claims.policy_id, 'approve-prod-shell-write');
});


test('approval request lookup exposes approved token for polling clients', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  assert.equal(createdResponse.status, 202);
  const created = await createdResponse.json() as { approval_id: string };

  const pendingResponse = await fetch(`${base}/v1/approval-requests/${created.approval_id}`, {
    headers: { authorization: 'Bearer dev-key' },
  });
  assert.equal(pendingResponse.status, 200);
  const pending = await pendingResponse.json() as { status: string; approval_token?: string };
  assert.equal(pending.status, 'pending');
  assert.equal(pending.approval_token, undefined);

  const approvedResponse = await post(base, `/v1/approval-requests/${created.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'platform_owner' });
  assert.equal(approvedResponse.status, 200);

  const lookupResponse = await fetch(`${base}/v1/approval-requests/${created.approval_id}`, {
    headers: { authorization: 'Bearer dev-key' },
  });
  assert.equal(lookupResponse.status, 200);
  const approved = await lookupResponse.json() as { status: string; approval_token?: string };
  assert.equal(approved.status, 'approved');
  assert.equal(typeof approved.approval_token, 'string');
});

test('rejecting a finalized approval returns conflict', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  const created = await createdResponse.json() as { approval_id: string };
  assert.equal((await post(base, `/v1/approval-requests/${created.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'platform_owner' })).status, 200);
  assert.equal((await post(base, `/v1/approval-requests/${created.approval_id}/reject`, { rejected_by: 'ross@example.com' })).status, 409);
});


test('server refuses partial signing-key loss', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-partial-key-'));
  const privateKeyFile = join(dir, 'private.pem');
  await writeFile(privateKeyFile, 'not-a-real-key');
  await assert.rejects(
    () =>
      startServer({
        host: '127.0.0.1',
        port: 0,
        policyFile: 'examples/policies/default.json',
        auditFile: join(dir, 'audit.jsonl'),
        privateKeyFile,
        publicKeyFile: join(dir, 'public.pem'),
        enableShellExecution: false,
        shellTimeoutMs: 1000,
        httpTimeoutMs: 1000,
        apiKeys: [],
      }),
    /Partial approval signing key loss/,
  );
});
