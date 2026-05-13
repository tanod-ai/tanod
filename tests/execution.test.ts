import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createAdapterRegistry } from '../src/adapters.js';
import { AuditLog } from '../src/audit.js';
import type { PolicyFile, ToolCallRequest } from '../src/domain.js';
import { executeGovernedToolCall } from '../src/execution.js';
import { generateSigningKeyPair, signApproval } from '../src/signing.js';

const policyFile = JSON.parse(await readFile('examples/policies/default.json', 'utf8')) as PolicyFile;

async function request(path: string): Promise<ToolCallRequest> {
  return JSON.parse(await readFile(path, 'utf8')) as ToolCallRequest;
}

async function auditLog(): Promise<AuditLog> {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-execution-'));
  return new AuditLog(join(dir, 'audit.jsonl'));
}

test('execution blocks denied requests before adapter execution', async () => {
  const keys = generateSigningKeyPair();
  const base = await request('examples/requests/shell-write-prod.json');
  const denied: ToolCallRequest = { ...base, request_id: 'req_denied_execution', arguments: { command: 'rm -rf /' } };
  const response = await executeGovernedToolCall({
    input: { request: denied },
    policyFile,
    auditLog: await auditLog(),
    adapters: createAdapterRegistry({ enableShellExecution: true, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }),
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(response.executed, false);
  assert.equal(response.result.status, 'blocked');
  assert.equal(response.decision.decision, 'deny');
});

test('execution blocks approval-required requests without token', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/shell-write-prod.json');
  const response = await executeGovernedToolCall({
    input: { request: toolCall },
    policyFile,
    auditLog: await auditLog(),
    adapters: createAdapterRegistry({ enableShellExecution: false, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }),
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(response.executed, false);
  assert.equal(response.result.status, 'blocked');
  assert.match(response.result.error ?? '', /Approval token required/);
});

test('execution verifies approval token before invoking adapter', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/shell-write-prod.json');
  const { token } = signApproval(
    {
      request: toolCall,
      approved_by: 'ross@example.com',
      approved_role: 'platform_owner',
      policy_id: 'approve-prod-shell-write',
      risk_level: 'L3',
      ttl_seconds: 900,
    },
    keys.privateKeyPem,
  );

  const response = await executeGovernedToolCall({
    input: { request: toolCall, approval_token: token },
    policyFile,
    auditLog: await auditLog(),
    adapters: createAdapterRegistry({ enableShellExecution: false, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }),
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(response.approval?.approved_by, 'ross@example.com');
  assert.equal(response.result.status, 'blocked');
  assert.match(response.result.error ?? '', /Shell execution is disabled/);
});

test('execution rejects approval token if request arguments change', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/shell-write-prod.json');
  const { token } = signApproval(
    {
      request: toolCall,
      approved_by: 'ross@example.com',
      policy_id: 'approve-prod-shell-write',
      risk_level: 'L3',
      ttl_seconds: 900,
    },
    keys.privateKeyPem,
  );
  const tampered: ToolCallRequest = { ...toolCall, arguments: { command: 'sudo systemctl stop openclaw-gateway' } };
  const log = await auditLog();
  await assert.rejects(
    () =>
      executeGovernedToolCall({
        input: { request: tampered, approval_token: token },
        policyFile,
        auditLog: log,
        adapters: createAdapterRegistry({ enableShellExecution: false, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }),
        publicKeyPem: keys.publicKeyPem,
      }),
    /argument hash does not match/,
  );
});

test('allowed shell command executes when shell adapter is explicitly enabled', async () => {
  const keys = generateSigningKeyPair();
  const toolCall = await request('examples/requests/shell-readonly.json');
  const safe: ToolCallRequest = { ...toolCall, request_id: 'req_echo', arguments: { command: 'whoami' } };
  const response = await executeGovernedToolCall({
    input: { request: safe },
    policyFile,
    auditLog: await auditLog(),
    adapters: createAdapterRegistry({ enableShellExecution: true, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }),
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(response.executed, true);
  assert.equal(response.result.status, 'success');
});
