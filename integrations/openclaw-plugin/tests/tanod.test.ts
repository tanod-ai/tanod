import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import {
  TanodClient,
  formatExecutionContent,
  isProtectedTool,
  mapGovernedExecParams,
  mapGovernedHttpParams,
  mapGovernedMcpParams,
  mapOpenClawToolCallToTanod,
  normalizeConfig,
} from '../src/tanod.js';

test('normalizes plugin config with environment API key fallback', () => {
  const config = normalizeConfig({ mode: 'governed_replacement', tanodUrl: 'http://tanod.local///', protectedTools: ['exec'] }, { TANOD_API_KEY: 'secret' });
  assert.equal(config.mode, 'governed_replacement');
  assert.equal(config.tanodUrl, 'http://tanod.local');
  assert.equal(config.apiKey, 'secret');
  assert.equal(isProtectedTool('EXEC', config), true);
  assert.equal(isProtectedTool('web_fetch', config), false);
});

test('maps OpenClaw exec tool call to Tanod shell.exec request', () => {
  const config = normalizeConfig({ actorId: 'ross', agentId: 'openclaw-main', defaultEnvironment: 'prod' });
  const request = mapOpenClawToolCallToTanod(
    {
      toolName: 'exec',
      params: { argv: ['systemctl', 'status', 'openclaw-gateway'], reason: 'diagnose gateway' },
      toolCallId: 'call_1',
      runId: 'run_1',
      context: { agentId: 'sherlock', sessionKey: 'main' },
    },
    config,
  );
  assert.equal(request.actor.user_id, 'ross');
  assert.equal(request.agent.agent_id, 'sherlock');
  assert.equal(request.tool.name, 'shell.exec');
  assert.equal(request.tool.operation, 'execute');
  assert.equal(request.target?.environment, 'prod');
  assert.deepEqual(request.arguments.argv, ['systemctl', 'status', 'openclaw-gateway']);
});

test('maps OpenClaw file mutation calls to OpenClaw namespaced Tanod requests', () => {
  const request = mapOpenClawToolCallToTanod(
    { toolName: 'apply_patch', params: { path: 'src/index.ts', patch: '...' } },
    normalizeConfig({}),
  );
  assert.equal(request.tool.name, 'openclaw.apply_patch');
  assert.equal(request.tool.category, 'filesystem');
  assert.equal(request.target?.resource, 'src/index.ts');
});

test('maps governed replacement tool params to Tanod adapter requests', () => {
  const config = normalizeConfig({ actorId: 'ross' });
  assert.equal(mapGovernedExecParams({ argv: ['ls', '-la'] }, config).tool.name, 'shell.exec');
  assert.equal(mapGovernedHttpParams({ url: 'https://example.com' }, config).tool.name, 'http.request');
  assert.equal(mapGovernedMcpParams({ server_url: 'https://mcp.example.com', tool_name: 'search' }, config).tool.name, 'mcp.call_tool');
});

test('Tanod client sends bearer auth and parses decisions', async () => {
  const server = createServer(async (request, response) => {
    assert.equal(request.method, 'POST');
    assert.equal(request.headers.authorization, 'Bearer secret');
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ request_id: 'req_1', decision: 'allow', risk_level: 'L1', policy_ids: [], argument_hash: 'sha256:x', message: 'ok' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    assert.equal(typeof address, 'object');
    const client = new TanodClient(normalizeConfig({ tanodUrl: `http://127.0.0.1:${(address as { port: number }).port}`, apiKey: 'secret' }));
    const decision = await client.decide(mapGovernedExecParams({ argv: ['true'] }, normalizeConfig({})));
    assert.equal(decision.decision, 'allow');
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});

test('formats approval-required execution result with approval id', () => {
  const text = formatExecutionContent(
    {
      request_id: 'req_1',
      executed: false,
      decision: { request_id: 'req_1', decision: 'require_approval', risk_level: 'L3', policy_ids: ['p1'], argument_hash: 'sha256:x', message: 'approval needed' },
      result: { status: 'blocked', adapter: 'tanod', error: 'Approval token required before execution.' },
    },
    { approval_id: 'appr_123', request_id: 'req_1', status: 'pending' },
  );
  assert.match(text, /approval is granted/);
  assert.match(text, /appr_123/);
});
