import { randomUUID } from 'node:crypto';
import pg from 'pg';
import type { AuditEvent, DecisionResponse, ToolCallRequest } from './domain.js';

const { Pool } = pg;

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';

export interface ApprovalRequestRecord {
  approval_id: string;
  request_id: string;
  status: ApprovalStatus;
  request: ToolCallRequest;
  decision: DecisionResponse;
  argument_hash: string;
  requested_by: string;
  approved_by?: string;
  approved_role?: string;
  rejected_by?: string;
  rejection_reason?: string;
  approval_token?: string;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ApprovalCreateInput {
  request: ToolCallRequest;
  decision: DecisionResponse;
  requested_by: string;
}

export interface ApprovalApproveInput {
  approved_by: string;
  approved_role?: string;
  approval_token: string;
  expires_at: string;
}

export interface ApprovalRejectInput {
  rejected_by: string;
  reason?: string;
}

export interface Storage {
  initialize(): Promise<void>;
  close(): Promise<void>;
  recordDecision(request: ToolCallRequest, decision: DecisionResponse): Promise<void>;
  createApprovalRequest(input: ApprovalCreateInput): Promise<ApprovalRequestRecord>;
  listApprovalRequests(status?: ApprovalStatus): Promise<ApprovalRequestRecord[]>;
  getApprovalRequest(approvalId: string): Promise<ApprovalRequestRecord | undefined>;
  approveApprovalRequest(approvalId: string, input: ApprovalApproveInput): Promise<ApprovalRequestRecord>;
  rejectApprovalRequest(approvalId: string, input: ApprovalRejectInput): Promise<ApprovalRequestRecord>;
  recordAuditEvent(event: AuditEvent): Promise<void>;
  getLatestAuditHash(): Promise<string | null>;
}

export class MemoryStorage implements Storage {
  private approvals = new Map<string, ApprovalRequestRecord>();
  private decisions = new Map<string, { request: ToolCallRequest; decision: DecisionResponse }>();
  private auditEvents = new Map<string, AuditEvent>();

  async initialize(): Promise<void> {}
  async close(): Promise<void> {}

  async recordDecision(request: ToolCallRequest, decision: DecisionResponse): Promise<void> {
    this.decisions.set(request.request_id, { request, decision });
  }

  async createApprovalRequest(input: ApprovalCreateInput): Promise<ApprovalRequestRecord> {
    const now = new Date().toISOString();
    const record: ApprovalRequestRecord = {
      approval_id: `appr_${randomUUID()}`,
      request_id: input.request.request_id,
      status: 'pending',
      request: input.request,
      decision: input.decision,
      argument_hash: input.decision.argument_hash,
      requested_by: input.requested_by,
      created_at: now,
      updated_at: now,
    };
    this.approvals.set(record.approval_id, record);
    return record;
  }

  async listApprovalRequests(status?: ApprovalStatus): Promise<ApprovalRequestRecord[]> {
    return [...this.approvals.values()].filter((record) => !status || record.status === status);
  }

  async getApprovalRequest(approvalId: string): Promise<ApprovalRequestRecord | undefined> {
    return this.approvals.get(approvalId);
  }

  async approveApprovalRequest(approvalId: string, input: ApprovalApproveInput): Promise<ApprovalRequestRecord> {
    const existing = await this.requireApproval(approvalId);
    const updated: ApprovalRequestRecord = {
      ...existing,
      status: 'approved',
      approved_by: input.approved_by,
      approved_role: input.approved_role,
      approval_token: input.approval_token,
      expires_at: input.expires_at,
      updated_at: new Date().toISOString(),
    };
    this.approvals.set(approvalId, updated);
    return updated;
  }

  async rejectApprovalRequest(approvalId: string, input: ApprovalRejectInput): Promise<ApprovalRequestRecord> {
    const existing = await this.requireApproval(approvalId);
    const updated: ApprovalRequestRecord = {
      ...existing,
      status: 'rejected',
      rejected_by: input.rejected_by,
      rejection_reason: input.reason,
      updated_at: new Date().toISOString(),
    };
    this.approvals.set(approvalId, updated);
    return updated;
  }

  async recordAuditEvent(event: AuditEvent): Promise<void> {
    this.auditEvents.set(event.event_id, event);
  }

  async getLatestAuditHash(): Promise<string | null> {
    const events = [...this.auditEvents.values()];
    return events.at(-1)?.event_hash ?? null;
  }

  private async requireApproval(approvalId: string): Promise<ApprovalRequestRecord> {
    const record = this.approvals.get(approvalId);
    if (!record) throw new Error(`Approval request not found: ${approvalId}`);
    if (record.status !== 'pending') throw new Error(`Approval request ${approvalId} is already ${record.status}.`);
    return record;
  }
}

export class PostgresStorage implements Storage {
  private readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async initialize(): Promise<void> {
    await this.pool.query(SCHEMA_SQL);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async recordDecision(request: ToolCallRequest, decision: DecisionResponse): Promise<void> {
    await this.pool.query(
      `INSERT INTO tanod_tool_calls (request_id, request, decision)
       VALUES ($1, $2::jsonb, $3::jsonb)
       ON CONFLICT (request_id) DO UPDATE SET request = EXCLUDED.request, decision = EXCLUDED.decision`,
      [request.request_id, JSON.stringify(request), JSON.stringify(decision)],
    );
  }

  async createApprovalRequest(input: ApprovalCreateInput): Promise<ApprovalRequestRecord> {
    const approvalId = `appr_${randomUUID()}`;
    const result = await this.pool.query(
      `INSERT INTO tanod_approval_requests
        (approval_id, request_id, status, request, decision, argument_hash, requested_by)
       VALUES ($1, $2, 'pending', $3::jsonb, $4::jsonb, $5, $6)
       RETURNING *`,
      [
        approvalId,
        input.request.request_id,
        JSON.stringify(input.request),
        JSON.stringify(input.decision),
        input.decision.argument_hash,
        input.requested_by,
      ],
    );
    return rowToApproval(result.rows[0]);
  }

  async listApprovalRequests(status?: ApprovalStatus): Promise<ApprovalRequestRecord[]> {
    const result = status
      ? await this.pool.query(`SELECT * FROM tanod_approval_requests WHERE status = $1 ORDER BY created_at DESC`, [status])
      : await this.pool.query(`SELECT * FROM tanod_approval_requests ORDER BY created_at DESC`);
    return result.rows.map(rowToApproval);
  }

  async getApprovalRequest(approvalId: string): Promise<ApprovalRequestRecord | undefined> {
    const result = await this.pool.query(`SELECT * FROM tanod_approval_requests WHERE approval_id = $1`, [approvalId]);
    return result.rows[0] ? rowToApproval(result.rows[0]) : undefined;
  }

  async approveApprovalRequest(approvalId: string, input: ApprovalApproveInput): Promise<ApprovalRequestRecord> {
    const result = await this.pool.query(
      `UPDATE tanod_approval_requests
       SET status = 'approved', approved_by = $2, approved_role = $3, approval_token = $4, expires_at = $5, updated_at = now()
       WHERE approval_id = $1 AND status = 'pending'
       RETURNING *`,
      [approvalId, input.approved_by, input.approved_role ?? null, input.approval_token, input.expires_at],
    );
    if (!result.rows[0]) throw new Error(`Approval request ${approvalId} was not found or is no longer pending.`);
    return rowToApproval(result.rows[0]);
  }

  async rejectApprovalRequest(approvalId: string, input: ApprovalRejectInput): Promise<ApprovalRequestRecord> {
    const result = await this.pool.query(
      `UPDATE tanod_approval_requests
       SET status = 'rejected', rejected_by = $2, rejection_reason = $3, updated_at = now()
       WHERE approval_id = $1 AND status = 'pending'
       RETURNING *`,
      [approvalId, input.rejected_by, input.reason ?? null],
    );
    if (!result.rows[0]) throw new Error(`Approval request ${approvalId} was not found or is no longer pending.`);
    return rowToApproval(result.rows[0]);
  }

  async recordAuditEvent(event: AuditEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO tanod_audit_events (event_id, event_type, request_id, previous_hash, event_hash, event)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       ON CONFLICT (event_id) DO NOTHING`,
      [event.event_id, event.event_type, event.request_id ?? null, event.previous_hash ?? null, event.event_hash, JSON.stringify(event)],
    );
  }

  async getLatestAuditHash(): Promise<string | null> {
    const result = await this.pool.query<{ event_hash: string }>(
      `SELECT event_hash FROM tanod_audit_events ORDER BY created_at DESC, event_id DESC LIMIT 1`,
    );
    return result.rows[0]?.event_hash ?? null;
  }
}

export function createStorageFromEnv(env: NodeJS.ProcessEnv): Storage {
  if (env.TANOD_DATABASE_URL) return new PostgresStorage(env.TANOD_DATABASE_URL);
  return new MemoryStorage();
}

function rowToApproval(row: Record<string, unknown>): ApprovalRequestRecord {
  return {
    approval_id: String(row.approval_id),
    request_id: String(row.request_id),
    status: row.status as ApprovalStatus,
    request: row.request as ToolCallRequest,
    decision: row.decision as DecisionResponse,
    argument_hash: String(row.argument_hash),
    requested_by: String(row.requested_by),
    approved_by: row.approved_by ? String(row.approved_by) : undefined,
    approved_role: row.approved_role ? String(row.approved_role) : undefined,
    rejected_by: row.rejected_by ? String(row.rejected_by) : undefined,
    rejection_reason: row.rejection_reason ? String(row.rejection_reason) : undefined,
    approval_token: row.approval_token ? String(row.approval_token) : undefined,
    expires_at: row.expires_at ? new Date(row.expires_at as string | Date).toISOString() : undefined,
    created_at: new Date(row.created_at as string | Date).toISOString(),
    updated_at: new Date(row.updated_at as string | Date).toISOString(),
  };
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS tanod_tool_calls (
  request_id TEXT PRIMARY KEY,
  request JSONB NOT NULL,
  decision JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tanod_approval_requests (
  approval_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  request JSONB NOT NULL,
  decision JSONB NOT NULL,
  argument_hash TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  approved_role TEXT,
  rejected_by TEXT,
  rejection_reason TEXT,
  approval_token TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tanod_approval_requests_status_idx ON tanod_approval_requests(status);
CREATE INDEX IF NOT EXISTS tanod_approval_requests_request_id_idx ON tanod_approval_requests(request_id);

CREATE TABLE IF NOT EXISTS tanod_audit_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  request_id TEXT,
  previous_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE,
  event JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tanod_audit_events_request_id_idx ON tanod_audit_events(request_id);
CREATE INDEX IF NOT EXISTS tanod_audit_events_event_type_idx ON tanod_audit_events(event_type);
`;
