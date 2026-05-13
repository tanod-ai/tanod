import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import type { ToolCallRequest } from '../src/domain.js';
import { generateSigningKeyPair, signApproval, verifyApprovalToken } from '../src/signing.js';

async function request(path: string): Promise<ToolCallRequest> {
  return JSON.parse(await readFile(path, 'utf8')) as ToolCallRequest;
}

test('signed approval token verifies for exact same request', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/identity-admin-grant.json');
  const { token, claims } = signApproval(
    {
      request: toolCall,
      approved_by: 'ross@example.com',
      approved_role: 'system_owner',
      policy_id: 'approve-admin-role-grants',
      risk_level: 'L4',
      ttl_seconds: 900,
    },
    keys.privateKeyPem,
  );
  const verified = verifyApprovalToken(token, keys.publicKeyPem, toolCall);
  assert.equal(verified.approval_id, claims.approval_id);
  assert.equal(verified.tool_args_hash, claims.tool_args_hash);
});

test('signed approval token rejects changed arguments', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/identity-admin-grant.json');
  const { token } = signApproval(
    {
      request: toolCall,
      approved_by: 'ross@example.com',
      approved_role: 'system_owner',
      policy_id: 'approve-admin-role-grants',
      risk_level: 'L4',
      ttl_seconds: 900,
    },
    keys.privateKeyPem,
  );

  const tampered: ToolCallRequest = {
    ...toolCall,
    arguments: { ...toolCall.arguments, user: 'jane@example.com' },
  };
  assert.throws(() => verifyApprovalToken(token, keys.publicKeyPem, tampered), /argument hash does not match/);
});

test('signed approval token rejects expiry', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/identity-admin-grant.json');
  const { token, claims } = signApproval(
    {
      request: toolCall,
      approved_by: 'ross@example.com',
      policy_id: 'approve-admin-role-grants',
      risk_level: 'L4',
      ttl_seconds: 1,
    },
    keys.privateKeyPem,
  );
  assert.throws(() => verifyApprovalToken(token, keys.publicKeyPem, toolCall, claims.exp + 1), /expired/);
});
