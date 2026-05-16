import { mkdir, readFile, appendFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256Hex } from './canonical.js';
import type { AuditEvent } from './domain.js';
import type { Storage } from './storage.js';

export class AuditLog {
  private previousHash: string | null = null;
  private initialized = false;
  private initializePromise?: Promise<void>;
  private appendQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly storage?: Storage,
  ) {}

  async append(event: Omit<AuditEvent, 'event_id' | 'timestamp' | 'previous_hash' | 'event_hash'>): Promise<AuditEvent> {
    const operation = this.appendQueue.then(() => this.appendNow(event));
    this.appendQueue = operation.catch(() => undefined);
    return operation;
  }

  private async appendNow(event: Omit<AuditEvent, 'event_id' | 'timestamp' | 'previous_hash' | 'event_hash'>): Promise<AuditEvent> {
    await this.initialize();
    const unsigned: AuditEvent = {
      event_id: `evt_${randomUUID()}`,
      timestamp: new Date().toISOString(),
      previous_hash: this.previousHash,
      ...event,
    };
    const eventHash = `sha256:${sha256Hex(canonicalize(unsigned))}`;
    const signed: AuditEvent = { ...unsigned, event_hash: eventHash };
    await mkdir(dirname(this.filePath), { recursive: true });
    const line = `${JSON.stringify(signed)}\n`;
    await appendFile(this.filePath, line, 'utf8');
    try {
      await this.storage?.recordAuditEvent(signed);
    } catch (error) {
      await rollbackJsonlAppend(this.filePath, line);
      throw error;
    }
    this.previousHash = eventHash;
    return signed;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    this.initializePromise ??= this.initializeNow();
    await this.initializePromise;
  }

  async listEvents(options: { event_type?: string; request_id?: string; limit?: number } = {}): Promise<AuditEvent[]> {
    await this.initialize();
    let raw = '';
    try {
      raw = await readFile(this.filePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return (await this.storage?.listAuditEvents(options)) ?? [];
      throw error;
    }
    const events = raw
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as AuditEvent)
      .filter((event) => !options.event_type || event.event_type === options.event_type)
      .filter((event) => !options.request_id || event.request_id === options.request_id)
      .reverse();
    return events.slice(0, normalizeLimit(options.limit));
  }

  private async initializeNow(): Promise<void> {
    if (this.initialized) return;
    try {
      const raw = await readFile(this.filePath, 'utf8');
      const lines = raw.split('\n').filter(Boolean);
      let fileHash: string | null = null;
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]) as AuditEvent;
        fileHash = last.event_hash ?? null;
      }
      await this.initializeFromHashes(fileHash);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await this.initializeFromHashes(null);
    }
  }

  private async initializeFromHashes(fileHash: string | null): Promise<void> {
    const storageHash = (await this.storage?.getLatestAuditHash()) ?? null;
    if (fileHash && storageHash && fileHash !== storageHash) {
      throw new Error('Audit chain head mismatch between JSONL file and durable storage. Refusing to append.');
    }
    this.previousHash = fileHash ?? storageHash;
    this.initialized = true;
  }
}

async function rollbackJsonlAppend(filePath: string, line: string): Promise<void> {
  const raw = await readFile(filePath, 'utf8');
  if (!raw.endsWith(line)) return;
  await writeFile(filePath, raw.slice(0, -line.length), 'utf8');
}

function normalizeLimit(limit: number | undefined): number {
  if (limit === undefined) return 100;
  if (!Number.isInteger(limit) || limit < 1) return 100;
  return Math.min(limit, 500);
}

export function verifyAuditChain(events: AuditEvent[]): boolean {
  let previous: string | null = null;
  for (const event of events) {
    const { event_hash: eventHash, ...withoutHash } = event;
    if (withoutHash.previous_hash !== previous) return false;
    const expected = `sha256:${sha256Hex(canonicalize(withoutHash))}`;
    if (eventHash !== expected) return false;
    previous = eventHash ?? null;
  }
  return true;
}
