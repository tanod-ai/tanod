import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { evaluatePolicy } from '../src/policy.js';
import type { PolicyFile, ToolCallRequest } from '../src/domain.js';

const policyFile = JSON.parse(await readFile('examples/policies/default.json', 'utf8')) as PolicyFile;

async function request(path: string): Promise<ToolCallRequest> {
  return JSON.parse(await readFile(path, 'utf8')) as ToolCallRequest;
}

test('allows read-only diagnostic shell commands', async () => {
  const decision = evaluatePolicy(policyFile, await request('examples/requests/shell-readonly.json'));
  assert.equal(decision.decision, 'allow');
  assert.equal(decision.risk_level, 'L1');
  assert.deepEqual(decision.policy_ids, ['allow-readonly-diagnostics']);
});

test('requires approval for production shell write commands', async () => {
  const decision = evaluatePolicy(policyFile, await request('examples/requests/shell-write-prod.json'));
  assert.equal(decision.decision, 'require_approval');
  assert.equal(decision.risk_level, 'L3');
  assert.deepEqual(decision.policy_ids, ['approve-prod-shell-write']);
  assert.match(decision.argument_hash, /^sha256:/);
});

test('blocks destructive shell commands before approval policies', async () => {
  const base = await request('examples/requests/shell-write-prod.json');
  const destructive: ToolCallRequest = {
    ...base,
    request_id: 'req_destructive',
    arguments: { command: 'rm -rf /' },
  };
  const decision = evaluatePolicy(policyFile, destructive);
  assert.equal(decision.decision, 'deny');
  assert.equal(decision.risk_level, 'L4');
  assert.deepEqual(decision.policy_ids, ['block-destructive-shell']);
});

test('requires approval for admin role grants', async () => {
  const decision = evaluatePolicy(policyFile, await request('examples/requests/identity-admin-grant.json'));
  assert.equal(decision.decision, 'require_approval');
  assert.equal(decision.risk_level, 'L4');
  assert.deepEqual(decision.policy_ids, ['approve-admin-role-grants']);
});
