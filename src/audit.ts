import { mkdir, readFile, appendFile } from 'node:fs/promises';
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
    await appendFile(this.filePath, `${JSON.stringify(signed)}\n`, 'utf8');
    await this.storage?.recordAuditEvent(signed);
    this.previousHash = eventHash;
    return signed;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    this.initializePromise ??= this.initializeNow();
    await this.initializePromise;
  }

  private async initializeNow(): Promise<void> {
    if (this.initialized) return;
    try {
      const raw = await readFile(this.filePath, 'utf8');
      const lines = raw.split('\n').filter(Boolean);
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]) as AuditEvent;
        this.previousHash = last.event_hash ?? null;
      }
      this.initialized = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      this.initialized = true;
    }
  }
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
