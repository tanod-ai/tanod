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
