import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
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
  const dir = await mkdtemp(join(tmpdir(), 'tanod-core-'));
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
    apiKeyRoles: { 'dev-key': ['Viewer', 'Approver', 'platform_owner'] },
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
  assert.equal(missingRole.status, 200);

  const secondCreatedResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  const secondCreated = await secondCreatedResponse.json() as { approval_id: string };
  const wrongRole = await post(base, `/v1/approval-requests/${secondCreated.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'viewer' });
  assert.equal(wrongRole.status, 403);

  const thirdCreatedResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  const thirdCreated = await thirdCreatedResponse.json() as { approval_id: string };
  const approved = await post(base, `/v1/approval-requests/${thirdCreated.approval_id}/approve`, { approved_by: 'ross@example.com', approved_role: 'platform_owner' });
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
  const policiesResponse = await fetch(`${base}/v1/policies`, { headers: { authorization: 'Bearer noroles-key' } });
  assert.equal(policiesResponse.status, 403);

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

test('console read endpoints expose policies, audit events, and agent summaries', async (t) => {
  const base = await withServer(t);
  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' });
  assert.equal(createdResponse.status, 202);

  const policiesResponse = await fetch(`${base}/v1/policies`, { headers: { authorization: 'Bearer dev-key' } });
  assert.equal(policiesResponse.status, 200);
  const policies = await policiesResponse.json() as { policies: Array<{ id: string }> };
  assert.ok(policies.policies.some((policy) => policy.id === 'approve-prod-shell-write'));

  const auditResponse = await fetch(`${base}/v1/audit-events?limit=10`, { headers: { authorization: 'Bearer dev-key' } });
  assert.equal(auditResponse.status, 200);
  const audit = await auditResponse.json() as { audit_events: Array<{ event_type: string; request_id?: string }> };
  assert.ok(audit.audit_events.some((event) => event.event_type === 'approval.requested' && event.request_id === toolCall.request_id));

  const agentsResponse = await fetch(`${base}/v1/agents`, { headers: { authorization: 'Bearer dev-key' } });
  assert.equal(agentsResponse.status, 200);
  const agents = await agentsResponse.json() as { agents: Array<{ agent_id: string; pending_approval_count: number; tool_call_count: number }> };
  const agent = agents.agents.find((item) => item.agent_id === toolCall.agent.agent_id);
  assert.equal(agent?.pending_approval_count, 1);
  assert.equal(agent?.tool_call_count, 1);
});

test('credentialed CORS is restricted to configured origins', async (t) => {
  const base = await withServer(t, { consoleBaseUrl: 'https://console.example.com' });

  const allowed = await fetch(`${base}/v1/console-config`, { headers: { origin: 'https://console.example.com' } });
  assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://console.example.com');
  assert.equal(allowed.headers.get('access-control-allow-credentials'), 'true');

  const denied = await fetch(`${base}/v1/console-config`, { headers: { origin: 'https://evil.example.com' } });
  assert.equal(denied.headers.get('access-control-allow-origin'), null);
  assert.equal(denied.headers.get('access-control-allow-credentials'), null);

  const preflight = await fetch(`${base}/v1/console-config`, {
    method: 'OPTIONS',
    headers: { origin: 'https://evil.example.com', 'access-control-request-method': 'GET' },
  });
  assert.equal(preflight.status, 403);
});

test('OAuth2 start uses configured callback base for provider redirect', async (t) => {
  const base = await withServer(t, {
    oauth2CallbackBaseUrl: 'https://tanod.example.com',
    oauth2Providers: [{
      id: 'github',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authorizationUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userUrl: 'https://api.github.com/user',
    }],
  });

  const response = await fetch(base + '/v1/oauth2/github/start?redirect_uri=' + encodeURIComponent(base), { redirect: 'manual' });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get('location') ?? '');
  assert.equal(location.origin + location.pathname, 'https://github.com/login/oauth/authorize');
  assert.equal(location.searchParams.get('redirect_uri'), 'https://tanod.example.com/v1/oauth2/github/callback');
});

test('OAuth2 login requires an active user row', async (t) => {
  const provider = createHttpServer((request, response) => {
    if (request.url === '/token') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ access_token: 'provider-token' }));
      return;
    }
    if (request.url === '/user') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ login: 'ross' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve, reject) => provider.close((err) => (err ? reject(err) : resolve()))));
  const providerAddress = provider.address() as AddressInfo;
  const providerBase = `http://127.0.0.1:${providerAddress.port}`;
  const base = await withServer(t, {
    apiKeyRoles: { 'dev-key': ['Admin'] },
    oauth2Providers: [{
      id: 'github',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authorizationUrl: 'https://github.example/authorize',
      tokenUrl: `${providerBase}/token`,
      userUrl: `${providerBase}/user`,
    }],
  });

  async function oauthCallback(): Promise<{ location: URL; cookie: string }> {
    const start = await fetch(`${base}/v1/oauth2/github/start?redirect_uri=${encodeURIComponent(base)}`, { redirect: 'manual' });
    const state = new URL(start.headers.get('location') ?? '').searchParams.get('state') ?? '';
    const callback = await fetch(`${base}/v1/oauth2/github/callback?code=test-code&state=${encodeURIComponent(state)}`, { redirect: 'manual' });
    assert.equal(callback.status, 302);
    return {
      location: new URL(callback.headers.get('location') ?? ''),
      cookie: callback.headers.get('set-cookie') ?? '',
    };
  }

  const denied = await oauthCallback();
  assert.equal(denied.location.searchParams.get('oauth_error'), 'user_not_authorized');
  assert.equal(denied.location.searchParams.get('oauth_identity'), 'github:ross');
  assert.equal(denied.cookie, '');

  const created = await post(base, '/v1/users', { user_id: 'github:ross', display_name: 'Ross', roles: ['Viewer'] });
  assert.equal(created.status, 200);

  const allowed = await oauthCallback();
  assert.equal(allowed.location.searchParams.get('oauth_token'), null);
  assert.match(allowed.cookie, /tanod_session=tanod-oauth-session\./);
  assert.match(allowed.cookie, /HttpOnly/);
  assert.match(allowed.cookie, /SameSite=Lax/);

  const meResponse = await fetch(`${base}/v1/me`, { headers: { cookie: allowed.cookie.split(';')[0] } });
  assert.equal(meResponse.status, 200);
  const me = await meResponse.json() as { identity: string; roles: string[] };
  assert.equal(me.identity, 'github:ross');
  assert.deepEqual(me.roles, ['Viewer']);

  const logout = await fetch(`${base}/v1/oauth2/logout`, { method: 'POST' });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie') ?? '', /tanod_session=; Path=\/; HttpOnly; SameSite=Lax; Max-Age=0/);
});

test('OAuth2 cross-site console sessions use SameSite=None secure cookies', async (t) => {
  const provider = createHttpServer((request, response) => {
    if (request.url === '/token') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ access_token: 'provider-token' }));
      return;
    }
    if (request.url === '/user') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ login: 'ross' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve, reject) => provider.close((err) => (err ? reject(err) : resolve()))));
  const providerAddress = provider.address() as AddressInfo;
  const providerBase = `http://127.0.0.1:${providerAddress.port}`;
  const base = await withServer(t, {
    apiKeyRoles: { 'dev-key': ['Admin'] },
    consoleBaseUrl: 'https://console.example.com',
    oauth2CallbackBaseUrl: 'https://api.example.com',
    oauth2Providers: [{
      id: 'github',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authorizationUrl: 'https://github.example/authorize',
      tokenUrl: `${providerBase}/token`,
      userUrl: `${providerBase}/user`,
    }],
  });
  const created = await post(base, '/v1/users', { user_id: 'github:ross', display_name: 'Ross', roles: ['Viewer'] });
  assert.equal(created.status, 200);

  const start = await fetch(`${base}/v1/oauth2/github/start?redirect_uri=${encodeURIComponent('https://console.example.com/')}`, {
    redirect: 'manual',
    headers: { host: 'api.example.com', 'x-forwarded-proto': 'https' },
  });
  const state = new URL(start.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const callback = await fetch(`${base}/v1/oauth2/github/callback?code=test-code&state=${encodeURIComponent(state)}`, {
    redirect: 'manual',
    headers: { host: 'api.example.com', 'x-forwarded-proto': 'https' },
  });
  assert.equal(callback.status, 302);
  const cookie = callback.headers.get('set-cookie') ?? '';
  assert.match(cookie, /SameSite=None/);
  assert.match(cookie, /Secure/);
});

test('RBAC lets admins invite users and blocks viewers from approving', async (t) => {
  const base = await withServer(t, {
    apiKeys: ['admin-key', 'viewer-key', 'approver-key', 'platform-approver-key'],
    apiKeyRoles: { 'admin-key': ['Admin'], 'viewer-key': ['Viewer'], 'approver-key': ['Approver'], 'platform-approver-key': ['Approver', 'platform_owner'] },
    apiKeyIdentities: { 'admin-key': 'admin@example.com', 'viewer-key': 'viewer@example.com', 'approver-key': 'approver@example.com', 'platform-approver-key': 'platform-approver@example.com' },
  });

  const invitationsResponse = await post(
    base,
    '/v1/invitations',
    { invites: [{ email: 'one@example.com', role: 'Viewer' }, { email: 'two@example.com', role: 'Approver' }] },
    'admin-key',
  );
  assert.equal(invitationsResponse.status, 202);
  const invitations = await invitationsResponse.json() as { invitations: Array<{ email: string; roles: string[]; invite_url: string }> };
  assert.equal(invitations.invitations.length, 2);
  assert.deepEqual(invitations.invitations[1].roles, ['Approver']);

  const toolCall = await requestFixture('examples/requests/shell-write-prod.json');
  const createdResponse = await post(base, '/v1/approval-requests', { request: toolCall, requested_by: 'ross@example.com' }, 'admin-key');
  const created = await createdResponse.json() as { approval_id: string };

  const viewerApproval = await post(
    base,
    `/v1/approval-requests/${created.approval_id}/approve`,
    { approved_by: 'viewer@example.com', approved_role: 'Viewer' },
    'viewer-key',
  );
  assert.equal(viewerApproval.status, 403);

  const approverApproval = await post(
    base,
    `/v1/approval-requests/${created.approval_id}/approve`,
    { approved_by: 'approver@example.com' },
    'approver-key',
  );
  assert.equal(approverApproval.status, 403);

  const platformApproverApproval = await post(
    base,
    `/v1/approval-requests/${created.approval_id}/approve`,
    { approved_by: 'platform-approver@example.com' },
    'platform-approver-key',
  );
  assert.equal(platformApproverApproval.status, 200);
});

test('users may have multiple RBAC roles', async (t) => {
  const base = await withServer(t, {
    apiKeys: ['admin-key', 'multi-key'],
    apiKeyRoles: { 'admin-key': ['Admin'], 'multi-key': ['Viewer', 'Approver'] },
    apiKeyIdentities: { 'admin-key': 'admin@example.com', 'multi-key': 'multi@example.com' },
  });

  const created = await post(base, '/v1/users', { identity: 'multi@example.com', roles: ['Viewer', 'Approver'] }, 'admin-key');
  assert.equal(created.status, 200);
  const user = await created.json() as { roles: string[] };
  assert.deepEqual(user.roles, ['Viewer', 'Approver']);

  const meResponse = await fetch(`${base}/v1/me`, { headers: { authorization: 'Bearer multi-key' } });
  assert.equal(meResponse.status, 200);
  const me = await meResponse.json() as { roles: string[]; capabilities: { approve: boolean; administer: boolean } };
  assert.deepEqual(me.roles, ['Viewer', 'Approver']);
  assert.equal(me.capabilities.approve, true);
  assert.equal(me.capabilities.administer, false);
});

test('only admins can mutate policies', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-policy-rbac-'));
  const policyFile = join(dir, 'policy.json');
  await writeFile(policyFile, await readFile('examples/policies/default.json', 'utf8'));
  const base = await withServer(t, {
    policyFile,
    apiKeys: ['admin-key', 'viewer-key'],
    apiKeyRoles: { 'admin-key': ['Admin'], 'viewer-key': ['Viewer'] },
    apiKeyIdentities: { 'admin-key': 'admin@example.com', 'viewer-key': 'viewer@example.com' },
  });

  const newPolicy = {
    id: 'deny-test-tool',
    priority: 5,
    when: { 'tool.name': { equals: 'test.tool' } },
    then: { decision: 'deny', risk_level: 'L2' },
  };
  const viewerUpdate = await fetch(`${base}/v1/policies/deny-test-tool`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: 'Bearer viewer-key' },
    body: JSON.stringify(newPolicy),
  });
  assert.equal(viewerUpdate.status, 403);

  const adminUpdate = await fetch(`${base}/v1/policies/deny-test-tool`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: 'Bearer admin-key' },
    body: JSON.stringify(newPolicy),
  });
  assert.equal(adminUpdate.status, 200);

  const policiesResponse = await fetch(`${base}/v1/policies`, { headers: { authorization: 'Bearer viewer-key' } });
  const policies = await policiesResponse.json() as { policies: Array<{ id: string }> };
  assert.ok(policies.policies.some((policy) => policy.id === 'deny-test-tool'));
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
