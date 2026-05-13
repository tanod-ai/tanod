#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { verifyAuditChain } from './audit.js';
import type { AuditEvent } from './domain.js';

const baseUrl = process.env.TANOD_URL ?? 'http://127.0.0.1:8787';
const [, , command, ...args] = process.argv;

try {
  await main(command, args);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

async function main(cmd: string | undefined, args: string[]): Promise<void> {
  switch (cmd) {
    case 'decide':
      await postFile('/v1/decisions', args[0]);
      return;
    case 'execute':
      await postJson('/v1/executions', { request: await readJsonFile(args[0]), approval_token: readFlag(args, '--token') });
      return;
    case 'request-approval':
      await postJson('/v1/approval-requests', { request: await readJsonFile(args[0]), requested_by: readFlag(args, '--by') });
      return;
    case 'approvals':
      await get(`/v1/approval-requests${readFlag(args, '--status') ? `?status=${encodeURIComponent(readFlag(args, '--status')!)}` : ''}`);
      return;
    case 'approve':
      await postJson(`/v1/approval-requests/${encodeURIComponent(required(args[0], 'approval id'))}/approve`, {
        approved_by: required(readFlag(args, '--by'), '--by'),
        approved_role: readFlag(args, '--role'),
      });
      return;
    case 'reject':
      await postJson(`/v1/approval-requests/${encodeURIComponent(required(args[0], 'approval id'))}/reject`, {
        rejected_by: required(readFlag(args, '--by'), '--by'),
        reason: readFlag(args, '--reason'),
      });
      return;
    case 'audit-verify':
      await verifyAudit(args[0] ?? '.tanod/audit.jsonl');
      return;
    case 'help':
    case undefined:
      help();
      return;
    default:
      throw new Error(`Unknown command: ${cmd}. Run tanod help.`);
  }
}

async function postFile(path: string, filePath: string | undefined): Promise<void> {
  await postJson(path, await readJsonFile(filePath));
}

async function postJson(path: string, body: unknown): Promise<void> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  await printResponse(response);
}

async function get(path: string): Promise<void> {
  await printResponse(await fetch(`${baseUrl}${path}`));
}

async function printResponse(response: Response): Promise<void> {
  const text = await response.text();
  if (!response.ok) process.exitCode = 1;
  try {
    console.log(JSON.stringify(JSON.parse(text), null, 2));
  } catch {
    console.log(text);
  }
}

async function readJsonFile(path: string | undefined): Promise<unknown> {
  if (!path) throw new Error('JSON file path is required.');
  return JSON.parse(await readFile(path, 'utf8'));
}

async function verifyAudit(path: string): Promise<void> {
  const raw = await readFile(path, 'utf8');
  const events = raw.trim().length === 0 ? [] : raw.trim().split('\n').map((line) => JSON.parse(line) as AuditEvent);
  const valid = verifyAuditChain(events);
  console.log(JSON.stringify({ valid, events: events.length, file: path }, null, 2));
  if (!valid) process.exitCode = 1;
}

function readFlag(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function required(value: string | undefined, label: string): string {
  if (!value) throw new Error(`${label} is required.`);
  return value;
}

function help(): void {
  console.log(`tanod commands:
  tanod decide <request.json>
  tanod execute <request.json> [--token <approval-token>]
  tanod request-approval <request.json> [--by <user>]
  tanod approvals [--status pending|approved|rejected|expired]
  tanod approve <approval-id> --by <user> [--role <role>]
  tanod reject <approval-id> --by <user> [--reason <reason>]
  tanod audit-verify [audit.jsonl]

Environment:
  TANOD_URL=http://127.0.0.1:8787`);
}
