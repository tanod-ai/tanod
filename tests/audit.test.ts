import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AuditLog, verifyAuditChain } from '../src/audit.js';
import type { AuditEvent } from '../src/domain.js';

test('audit log writes a verifiable hash chain', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-'));
  const path = join(dir, 'audit.jsonl');
  const audit = new AuditLog(path);
  await audit.append({ event_type: 'decision.evaluated', request_id: 'req_1', decision: 'allow', risk_level: 'L1' });
  await audit.append({ event_type: 'approval.signed', request_id: 'req_1', approval_id: 'appr_1' });
  const events = (await readFile(path, 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as AuditEvent);
  assert.equal(events.length, 2);
  assert.equal(verifyAuditChain(events), true);
});

test('audit chain verification detects tampering', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-'));
  const path = join(dir, 'audit.jsonl');
  const audit = new AuditLog(path);
  await audit.append({ event_type: 'decision.evaluated', request_id: 'req_1', decision: 'allow', risk_level: 'L1' });
  const events = (await readFile(path, 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as AuditEvent);
  events[0].decision = 'deny';
  assert.equal(verifyAuditChain(events), false);
});
