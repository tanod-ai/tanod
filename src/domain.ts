export type Decision = 'allow' | 'deny' | 'require_approval';
export type RiskLevel = 'L0' | 'L1' | 'L2' | 'L3' | 'L4';

export interface ToolCallRequest {
  version: 'v1';
  request_id: string;
  timestamp?: string;
  actor: {
    user_id: string;
    roles?: string[];
  };
  agent: {
    agent_id: string;
    agent_type?: string;
    environment?: string;
  };
  tool: {
    name: string;
    category?: string;
    operation?: 'read' | 'write' | 'delete' | 'execute' | string;
    risk_hint?: RiskLevel | 'low' | 'medium' | 'high' | 'critical' | string;
  };
  target?: {
    system?: string;
    environment?: string;
    resource?: string;
  };
  arguments: Record<string, unknown>;
  context?: {
    reason?: string;
    user_prompt?: string;
    source_refs?: string[];
    [key: string]: unknown;
  };
}

export interface PolicyRule {
  id: string;
  description?: string;
  priority?: number;
  when: Record<string, MatchCondition>;
  then: {
    decision: Decision;
    risk_level?: RiskLevel;
    message?: string;
    approval?: {
      required_roles?: string[];
      token_ttl_seconds?: number;
    };
    audit?: {
      severity?: 'low' | 'medium' | 'high' | 'critical';
    };
  };
}

export interface PolicyFile {
  version: 'v1';
  default_decision?: Decision;
  default_risk_level?: RiskLevel;
  policies: PolicyRule[];
}

export type MatchCondition =
  | { equals: unknown }
  | { contains: string }
  | { contains_any: string[] }
  | { matches: string }
  | { in: unknown[] };

export interface ApprovalRequirements {
  required_roles: string[];
  token_ttl_seconds?: number;
}

export interface DecisionResponse {
  request_id: string;
  decision: Decision;
  risk_level: RiskLevel;
  policy_ids: string[];
  argument_hash: string;
  message: string;
  approval?: ApprovalRequirements;
}

export interface ApprovalTokenClaims {
  iss: 'tanod';
  sub: 'approval';
  aud: 'tanod-tool-proxy';
  approval_id: string;
  approved_by: string;
  approved_role?: string;
  agent_id: string;
  tool_name: string;
  tool_args_hash: string;
  risk_level: RiskLevel;
  policy_id: string;
  decision: 'approved';
  iat: number;
  exp: number;
}

export interface AuditEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  request_id?: string;
  actor_id?: string;
  agent_id?: string;
  tool_name?: string;
  decision?: Decision;
  risk_level?: RiskLevel;
  policy_ids?: string[];
  argument_hash?: string;
  approval_id?: string;
  result?: 'success' | 'failure' | 'blocked';
  details?: Record<string, unknown>;
  previous_hash?: string | null;
  event_hash?: string;
}
