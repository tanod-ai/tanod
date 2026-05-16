import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import type { AuditEvent, DecisionResponse, ToolCallRequest } from './domain.js';

const { Pool } = pg;

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';
export type UserRole = 'Admin' | 'Approver' | 'Viewer';

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

export interface ToolCallRecord {
  request_id: string;
  request: ToolCallRequest;
  decision: DecisionResponse;
  created_at: string;
}

export interface UserRecord {
  user_id: string;
  identity: string;
  display_name: string;
  roles: UserRole[];
  status: 'active' | 'disabled';
  created_at: string;
  updated_at: string;
}

export interface InvitationRecord {
  invitation_id: string;
  token: string;
  email: string;
  roles: UserRole[];
  invited_by: string;
  invite_url?: string;
  accepted_by?: string;
  accepted_at?: string;
  expires_at: string;
  created_at: string;
}

export interface Storage {
  initialize(): Promise<void>;
  close(): Promise<void>;
  recordDecision(request: ToolCallRequest, decision: DecisionResponse): Promise<void>;
  listToolCalls(): Promise<ToolCallRecord[]>;
  getUserByIdentity(identity: string): Promise<UserRecord | undefined>;
  listUsers(): Promise<UserRecord[]>;
  upsertUser(input: { identity: string; displayName?: string; roles: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord>;
  updateUser(userId: string, input: { displayName?: string; roles?: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord>;
  deleteUser(userId: string): Promise<void>;
  createInvitation(input: { email: string; roles: UserRole[]; invited_by: string; invite_url?: string; expires_at: string }): Promise<InvitationRecord>;
  listInvitations(): Promise<InvitationRecord[]>;
  getInvitationByToken(token: string): Promise<InvitationRecord | undefined>;
  acceptInvitation(token: string, identity: string): Promise<UserRecord>;
  createApprovalRequest(input: ApprovalCreateInput): Promise<ApprovalRequestRecord>;
  listApprovalRequests(status?: ApprovalStatus): Promise<ApprovalRequestRecord[]>;
  getApprovalRequest(approvalId: string): Promise<ApprovalRequestRecord | undefined>;
  approveApprovalRequest(approvalId: string, input: ApprovalApproveInput): Promise<ApprovalRequestRecord>;
  rejectApprovalRequest(approvalId: string, input: ApprovalRejectInput): Promise<ApprovalRequestRecord>;
  recordAuditEvent(event: AuditEvent): Promise<void>;
  listAuditEvents(options?: { event_type?: string; request_id?: string; limit?: number }): Promise<AuditEvent[]>;
  getLatestAuditHash(): Promise<string | null>;
}

export class MemoryStorage implements Storage {
  private approvals = new Map<string, ApprovalRequestRecord>();
  private decisions = new Map<string, ToolCallRecord>();
  private auditEvents = new Map<string, AuditEvent>();
  private users = new Map<string, UserRecord>();
  private invitations = new Map<string, InvitationRecord>();

  async initialize(): Promise<void> {}
  async close(): Promise<void> {}

  async recordDecision(request: ToolCallRequest, decision: DecisionResponse): Promise<void> {
    const existing = this.decisions.get(request.request_id);
    this.decisions.set(request.request_id, { request_id: request.request_id, request, decision, created_at: existing?.created_at ?? new Date().toISOString() });
  }

  async listToolCalls(): Promise<ToolCallRecord[]> {
    return [...this.decisions.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  async getUserByIdentity(identity: string): Promise<UserRecord | undefined> {
    return [...this.users.values()].find((user) => user.identity === identity);
  }

  async listUsers(): Promise<UserRecord[]> {
    return [...this.users.values()].sort((a, b) => a.identity.localeCompare(b.identity));
  }

  async upsertUser(input: { identity: string; displayName?: string; roles: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord> {
    const existing = await this.getUserByIdentity(input.identity);
    const now = new Date().toISOString();
    const record: UserRecord = {
      user_id: existing?.user_id ?? input.identity,
      identity: input.identity,
      display_name: input.displayName ?? existing?.display_name ?? input.identity,
      roles: input.roles,
      status: input.status ?? existing?.status ?? 'active',
      created_at: existing?.created_at ?? now,
      updated_at: now,
    };
    this.users.set(record.user_id, record);
    return record;
  }

  async updateUser(userId: string, input: { displayName?: string; roles?: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord> {
    const existing = this.users.get(userId) ?? await this.getUserByIdentity(userId);
    if (!existing) throw new Error(`User not found: ${userId}`);
    const updated = { ...existing, display_name: input.displayName ?? existing.display_name, roles: input.roles ?? existing.roles, status: input.status ?? existing.status, updated_at: new Date().toISOString() };
    this.users.set(existing.user_id, updated);
    return updated;
  }

  async deleteUser(userId: string): Promise<void> {
    const existing = this.users.get(userId) ?? await this.getUserByIdentity(userId);
    if (existing) this.users.delete(existing.user_id);
  }

  async createInvitation(input: { email: string; roles: UserRole[]; invited_by: string; invite_url?: string; expires_at: string }): Promise<InvitationRecord> {
    const token = randomToken();
    const record: InvitationRecord = {
      invitation_id: `inv_${randomUUID()}`,
      token,
      email: input.email,
      roles: input.roles,
      invited_by: input.invited_by,
      invite_url: input.invite_url,
      expires_at: input.expires_at,
      created_at: new Date().toISOString(),
    };
    this.invitations.set(token, record);
    return record;
  }

  async listInvitations(): Promise<InvitationRecord[]> {
    return [...this.invitations.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  async getInvitationByToken(token: string): Promise<InvitationRecord | undefined> {
    return this.invitations.get(token);
  }

  async acceptInvitation(token: string, identity: string): Promise<UserRecord> {
    const invitation = this.invitations.get(token);
    if (!invitation) throw new Error('Invitation not found.');
    if (invitation.accepted_at) throw new Error('Invitation has already been accepted.');
    if (Date.parse(invitation.expires_at) < Date.now()) throw new Error('Invitation has expired.');
    const user = await this.upsertUser({ identity, displayName: identity, roles: invitation.roles, status: 'active' });
    this.invitations.set(token, { ...invitation, accepted_by: identity, accepted_at: new Date().toISOString() });
    return user;
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

  async listAuditEvents(options: { event_type?: string; request_id?: string; limit?: number } = {}): Promise<AuditEvent[]> {
    return [...this.auditEvents.values()]
      .filter((event) => !options.event_type || event.event_type === options.event_type)
      .filter((event) => !options.request_id || event.request_id === options.request_id)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, normalizeLimit(options.limit));
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

  async listToolCalls(): Promise<ToolCallRecord[]> {
    const result = await this.pool.query(
      `SELECT request_id, request, decision, created_at FROM tanod_tool_calls ORDER BY created_at DESC`,
    );
    return result.rows.map((row) => ({
      request_id: String(row.request_id),
      request: row.request as ToolCallRequest,
      decision: row.decision as DecisionResponse,
      created_at: new Date(row.created_at as string | Date).toISOString(),
    }));
  }

  async getUserByIdentity(identity: string): Promise<UserRecord | undefined> {
    const result = await this.pool.query(`SELECT * FROM tanod_users WHERE identity = $1`, [identity]);
    return result.rows[0] ? rowToUser(result.rows[0]) : undefined;
  }

  async listUsers(): Promise<UserRecord[]> {
    const result = await this.pool.query(`SELECT * FROM tanod_users ORDER BY identity ASC`);
    return result.rows.map(rowToUser);
  }

  async upsertUser(input: { identity: string; displayName?: string; roles: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord> {
    const result = await this.pool.query(
      `INSERT INTO tanod_users (user_id, identity, display_name, role, roles, status)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)
       ON CONFLICT (identity) DO UPDATE SET display_name = EXCLUDED.display_name, role = EXCLUDED.role, roles = EXCLUDED.roles, status = EXCLUDED.status, updated_at = now()
       RETURNING *`,
      [input.identity, input.identity, input.displayName ?? input.identity, input.roles[0] ?? 'Viewer', JSON.stringify(input.roles), input.status ?? 'active'],
    );
    return rowToUser(result.rows[0]);
  }

  async updateUser(userId: string, input: { displayName?: string; roles?: UserRole[]; status?: 'active' | 'disabled' }): Promise<UserRecord> {
    const result = await this.pool.query(
      `UPDATE tanod_users
       SET display_name = COALESCE($2, display_name), role = COALESCE($3, role), roles = COALESCE($4::jsonb, roles), status = COALESCE($5, status), updated_at = now()
       WHERE user_id = $1 OR identity = $1
       RETURNING *`,
      [userId, input.displayName ?? null, input.roles?.[0] ?? null, input.roles ? JSON.stringify(input.roles) : null, input.status ?? null],
    );
    if (!result.rows[0]) throw new Error(`User not found: ${userId}`);
    return rowToUser(result.rows[0]);
  }

  async deleteUser(userId: string): Promise<void> {
    await this.pool.query(`DELETE FROM tanod_users WHERE user_id = $1 OR identity = $1`, [userId]);
  }

  async createInvitation(input: { email: string; roles: UserRole[]; invited_by: string; invite_url?: string; expires_at: string }): Promise<InvitationRecord> {
    const result = await this.pool.query(
      `INSERT INTO tanod_invitations (invitation_id, token, email, role, roles, invited_by, invite_url, expires_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
       RETURNING *`,
      [`inv_${randomUUID()}`, randomToken(), input.email, input.roles[0] ?? 'Viewer', JSON.stringify(input.roles), input.invited_by, input.invite_url ?? null, input.expires_at],
    );
    return rowToInvitation(result.rows[0]);
  }

  async listInvitations(): Promise<InvitationRecord[]> {
    const result = await this.pool.query(`SELECT * FROM tanod_invitations ORDER BY created_at DESC`);
    return result.rows.map(rowToInvitation);
  }

  async getInvitationByToken(token: string): Promise<InvitationRecord | undefined> {
    const result = await this.pool.query(`SELECT * FROM tanod_invitations WHERE token = $1`, [token]);
    return result.rows[0] ? rowToInvitation(result.rows[0]) : undefined;
  }

  async acceptInvitation(token: string, identity: string): Promise<UserRecord> {
    const invitation = await this.getInvitationByToken(token);
    if (!invitation) throw new Error('Invitation not found.');
    if (invitation.accepted_at) throw new Error('Invitation has already been accepted.');
    if (Date.parse(invitation.expires_at) < Date.now()) throw new Error('Invitation has expired.');
    const user = await this.upsertUser({ identity, displayName: identity, roles: invitation.roles, status: 'active' });
    await this.pool.query(`UPDATE tanod_invitations SET accepted_by = $2, accepted_at = now() WHERE token = $1`, [token, identity]);
    return user;
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

  async listAuditEvents(options: { event_type?: string; request_id?: string; limit?: number } = {}): Promise<AuditEvent[]> {
    const clauses: string[] = [];
    const values: unknown[] = [];
    if (options.event_type) {
      values.push(options.event_type);
      clauses.push(`event_type = $${values.length}`);
    }
    if (options.request_id) {
      values.push(options.request_id);
      clauses.push(`request_id = $${values.length}`);
    }
    values.push(normalizeLimit(options.limit));
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const result = await this.pool.query(
      `SELECT event FROM tanod_audit_events ${where} ORDER BY created_at DESC, event_id DESC LIMIT $${values.length}`,
      values,
    );
    return result.rows.map((row) => row.event as AuditEvent);
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

function normalizeLimit(limit: number | undefined): number {
  if (limit === undefined) return 100;
  if (!Number.isInteger(limit) || limit < 1) return 100;
  return Math.min(limit, 500);
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

function rowToUser(row: Record<string, unknown>): UserRecord {
  return {
    user_id: String(row.identity),
    identity: String(row.identity),
    display_name: row.display_name ? String(row.display_name) : String(row.identity),
    roles: normalizeRoles(row.roles ?? row.role),
    status: row.status as 'active' | 'disabled',
    created_at: new Date(row.created_at as string | Date).toISOString(),
    updated_at: new Date(row.updated_at as string | Date).toISOString(),
  };
}

function rowToInvitation(row: Record<string, unknown>): InvitationRecord {
  return {
    invitation_id: String(row.invitation_id),
    token: String(row.token),
    email: String(row.email),
    roles: normalizeRoles(row.roles ?? row.role),
    invited_by: String(row.invited_by),
    invite_url: row.invite_url ? String(row.invite_url) : undefined,
    accepted_by: row.accepted_by ? String(row.accepted_by) : undefined,
    accepted_at: row.accepted_at ? new Date(row.accepted_at as string | Date).toISOString() : undefined,
    expires_at: new Date(row.expires_at as string | Date).toISOString(),
    created_at: new Date(row.created_at as string | Date).toISOString(),
  };
}

function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

function normalizeRoles(value: unknown): UserRole[] {
  const raw = Array.isArray(value) ? value : typeof value === 'string' && value.startsWith('[') ? JSON.parse(value) as unknown[] : value ? [value] : [];
  const roles = raw.filter((role): role is UserRole => role === 'Admin' || role === 'Approver' || role === 'Viewer');
  return roles.length > 0 ? [...new Set(roles)] : ['Viewer'];
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

CREATE TABLE IF NOT EXISTS tanod_users (
  user_id TEXT PRIMARY KEY,
  identity TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('Admin', 'Approver', 'Viewer')),
  roles JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tanod_users_role_idx ON tanod_users(role);

CREATE TABLE IF NOT EXISTS tanod_invitations (
  invitation_id TEXT PRIMARY KEY,
  token TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('Admin', 'Approver', 'Viewer')),
  roles JSONB NOT NULL DEFAULT '[]'::jsonb,
  invited_by TEXT NOT NULL,
  invite_url TEXT,
  accepted_by TEXT,
  accepted_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tanod_invitations_email_idx ON tanod_invitations(email);
CREATE INDEX IF NOT EXISTS tanod_invitations_token_idx ON tanod_invitations(token);

ALTER TABLE tanod_users ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE tanod_users ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';
UPDATE tanod_users SET roles = to_jsonb(ARRAY[role]) WHERE roles = '[]'::jsonb;
UPDATE tanod_users SET display_name = identity WHERE display_name = '';
ALTER TABLE tanod_invitations ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '[]'::jsonb;
UPDATE tanod_invitations SET roles = to_jsonb(ARRAY[role]) WHERE roles = '[]'::jsonb;

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
