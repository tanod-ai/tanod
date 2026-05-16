import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AuditLog, verifyAuditChain } from '../src/audit.js';
import type { AuditEvent } from '../src/domain.js';
import { MemoryStorage } from '../src/storage.js';

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


test('audit log serializes concurrent appends into a valid chain', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-concurrent-'));
  const path = join(dir, 'audit.jsonl');
  const audit = new AuditLog(path);
  await Promise.all(
    Array.from({ length: 25 }, (_, index) =>
      audit.append({ event_type: 'decision.evaluated', request_id: `req_${index}`, decision: 'allow', risk_level: 'L1' }),
    ),
  );
  const events = (await readFile(path, 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as AuditEvent);
  assert.equal(events.length, 25);
  assert.equal(verifyAuditChain(events), true);
});


test('audit log continues from durable storage when JSONL file is missing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-storage-head-'));
  const path = join(dir, 'audit.jsonl');
  const storage = new MemoryStorage();
  const storedHead = 'sha256:stored-head';
  await storage.recordAuditEvent({
    event_id: 'evt_existing',
    event_type: 'decision.evaluated',
    timestamp: new Date().toISOString(),
    event_hash: storedHead,
  });
  const audit = new AuditLog(path, storage);
  const event = await audit.append({ event_type: 'decision.evaluated', request_id: 'req_after_storage', decision: 'allow', risk_level: 'L1' });
  assert.equal(event.previous_hash, storedHead);
});

test('audit log lists durable storage events when JSONL file is missing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-storage-list-'));
  const path = join(dir, 'audit.jsonl');
  const storage = new MemoryStorage();
  await storage.recordAuditEvent({
    event_id: 'evt_existing',
    event_type: 'approval.requested',
    timestamp: new Date().toISOString(),
    request_id: 'req_existing',
    event_hash: 'sha256:stored-head',
  });
  const audit = new AuditLog(path, storage);
  const events = await audit.listEvents({ request_id: 'req_existing' });
  assert.equal(events.length, 1);
  assert.equal(events[0].event_id, 'evt_existing');
});

test('audit log refuses mismatched JSONL and durable storage heads', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tanod-audit-mismatch-'));
  const path = join(dir, 'audit.jsonl');
  const storage = new MemoryStorage();
  await storage.recordAuditEvent({
    event_id: 'evt_existing',
    event_type: 'decision.evaluated',
    timestamp: new Date().toISOString(),
    event_hash: 'sha256:storage-head',
  });
  const audit = new AuditLog(path);
  await audit.append({ event_type: 'decision.evaluated', request_id: 'req_file', decision: 'allow', risk_level: 'L1' });
  const auditWithStorage = new AuditLog(path, storage);
  await assert.rejects(
    () => auditWithStorage.append({ event_type: 'decision.evaluated', request_id: 'req_reject', decision: 'allow', risk_level: 'L1' }),
    /Audit chain head mismatch/,
  );
});
