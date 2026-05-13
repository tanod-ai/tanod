import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import type { PolicyFile, ToolCallRequest } from '../src/domain.js';
import { evaluatePolicy } from '../src/policy.js';
import { MemoryStorage } from '../src/storage.js';

const policyFile = JSON.parse(await readFile('examples/policies/default.json', 'utf8')) as PolicyFile;
const toolCall = JSON.parse(await readFile('examples/requests/shell-write-prod.json', 'utf8')) as ToolCallRequest;

test('memory storage persists approval request lifecycle', async () => {
  const storage = new MemoryStorage();
  await storage.initialize();
  const decision = evaluatePolicy(policyFile, toolCall);
  await storage.recordDecision(toolCall, decision);
  const created = await storage.createApprovalRequest({ request: toolCall, decision, requested_by: 'ross@example.com' });
  assert.equal(created.status, 'pending');
  assert.equal((await storage.listApprovalRequests('pending')).length, 1);
  const approved = await storage.approveApprovalRequest(created.approval_id, {
    approved_by: 'ross@example.com',
    approved_role: 'platform_owner',
    approval_token: 'token',
    expires_at: new Date(Date.now() + 900_000).toISOString(),
  });
  assert.equal(approved.status, 'approved');
  assert.equal((await storage.listApprovalRequests('pending')).length, 0);
});
