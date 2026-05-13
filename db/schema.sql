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
