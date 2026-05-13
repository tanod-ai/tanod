export type TanodMode = 'gate_only' | 'governed_replacement';

export interface TanodPluginConfig {
  mode: TanodMode;
  tanodUrl: string;
  apiKey?: string;
  apiKeyEnv?: string;
  agentId: string;
  agentType: string;
  actorId: string;
  defaultEnvironment: string;
  protectedTools: string[];
  blockRawProtectedToolsInGovernedMode: boolean;
  createApprovalRequests: boolean;
  approvalRequestedBy: string;
  approvalTimeoutMs: number;
  approvalTimeoutBehavior: 'allow' | 'deny';
  approvalRole?: string;
  failClosed: boolean;
}

export interface OpenClawToolEvent {
  toolName: string;
  params: Record<string, unknown>;
  toolCallId?: string;
  runId?: string;
  context?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    jobId?: string;
    messageProvider?: string;
    channelId?: string;
    pluginConfig?: unknown;
    [key: string]: unknown;
  };
}

export interface TanodToolCallRequest {
  version: 'v1';
  request_id: string;
  timestamp: string;
  actor: { user_id: string; roles?: string[] };
  agent: { agent_id: string; agent_type?: string; environment?: string };
  tool: { name: string; category?: string; operation?: string; risk_hint?: string };
  target?: { system?: string; environment?: string; resource?: string };
  arguments: Record<string, unknown>;
  context?: Record<string, unknown>;
}

export interface TanodDecisionResponse {
  request_id: string;
  decision: 'allow' | 'deny' | 'require_approval';
  risk_level: 'L0' | 'L1' | 'L2' | 'L3' | 'L4';
  policy_ids: string[];
  argument_hash: string;
  message: string;
  approval?: { required_roles: string[]; token_ttl_seconds?: number };
}

export interface TanodExecutionResponse {
  request_id: string;
  decision: TanodDecisionResponse;
  executed: boolean;
  result: { status: 'success' | 'failure' | 'blocked'; adapter: string; output?: unknown; error?: string; metadata?: Record<string, unknown> };
  approval?: Record<string, unknown>;
}

export interface TanodApprovalRequestResponse {
  approval_id: string;
  request_id: string;
  status: string;
  [key: string]: unknown;
}

export const DEFAULT_CONFIG: TanodPluginConfig = {
  mode: 'gate_only',
  tanodUrl: 'http://127.0.0.1:8787',
  apiKeyEnv: 'TANOD_API_KEY',
  agentId: 'openclaw',
  agentType: 'openclaw-agent',
  actorId: 'openclaw-user',
  defaultEnvironment: 'dev',
  protectedTools: ['exec', 'bash', 'code_execution', 'apply_patch', 'write', 'edit', 'web_fetch', 'mcp.call_tool'],
  blockRawProtectedToolsInGovernedMode: true,
  createApprovalRequests: true,
  approvalRequestedBy: 'openclaw',
  approvalTimeoutMs: 600_000,
  approvalTimeoutBehavior: 'deny',
  failClosed: true,
};

export function normalizeConfig(raw: unknown, env: Record<string, string | undefined> = process.env): TanodPluginConfig {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const apiKeyEnv = stringValue(value.apiKeyEnv, DEFAULT_CONFIG.apiKeyEnv);
  const mode = value.mode === 'governed_replacement' ? 'governed_replacement' : 'gate_only';
  return {
    mode,
    tanodUrl: stringValue(value.tanodUrl, DEFAULT_CONFIG.tanodUrl).replace(/\/+$/, ''),
    apiKey: stringValue(value.apiKey, env[apiKeyEnv]),
    apiKeyEnv,
    agentId: stringValue(value.agentId, DEFAULT_CONFIG.agentId),
    agentType: stringValue(value.agentType, DEFAULT_CONFIG.agentType),
    actorId: stringValue(value.actorId, DEFAULT_CONFIG.actorId),
    defaultEnvironment: stringValue(value.defaultEnvironment, DEFAULT_CONFIG.defaultEnvironment),
    protectedTools: Array.isArray(value.protectedTools) ? value.protectedTools.map(String) : DEFAULT_CONFIG.protectedTools,
    blockRawProtectedToolsInGovernedMode: booleanValue(value.blockRawProtectedToolsInGovernedMode, DEFAULT_CONFIG.blockRawProtectedToolsInGovernedMode),
    createApprovalRequests: booleanValue(value.createApprovalRequests, DEFAULT_CONFIG.createApprovalRequests),
    approvalRequestedBy: stringValue(value.approvalRequestedBy, DEFAULT_CONFIG.approvalRequestedBy),
    approvalTimeoutMs: numberValue(value.approvalTimeoutMs, DEFAULT_CONFIG.approvalTimeoutMs),
    approvalTimeoutBehavior: value.approvalTimeoutBehavior === 'allow' ? 'allow' : 'deny',
    approvalRole: optionalString(value.approvalRole),
    failClosed: booleanValue(value.failClosed, DEFAULT_CONFIG.failClosed),
  };
}

export function isProtectedTool(toolName: string, config: TanodPluginConfig): boolean {
  const normalized = toolName.toLowerCase();
  return config.protectedTools.some((tool) => tool.toLowerCase() === normalized);
}

export function mapOpenClawToolCallToTanod(event: OpenClawToolEvent, config: TanodPluginConfig): TanodToolCallRequest {
  const requestId = safeId(`oc_${event.runId ?? event.context?.runId ?? 'run'}_${event.toolCallId ?? event.toolName}_${Date.now()}`);
  const mapped = mapToolIdentity(event.toolName, event.params);
  const targetEnvironment = stringFrom(event.params.targetEnvironment) ?? stringFrom(event.params.environment) ?? config.defaultEnvironment;
  return {
    version: 'v1',
    request_id: requestId,
    timestamp: new Date().toISOString(),
    actor: { user_id: config.actorId },
    agent: {
      agent_id: event.context?.agentId ?? config.agentId,
      agent_type: config.agentType,
      environment: config.defaultEnvironment,
    },
    tool: mapped.tool,
    target: {
      system: stringFrom(event.params.targetSystem) ?? mapped.targetSystem ?? 'openclaw',
      environment: targetEnvironment,
      resource: stringFrom(event.params.targetResource) ?? mapped.targetResource,
    },
    arguments: mapped.arguments,
    context: {
      openclaw_tool_name: event.toolName,
      openclaw_tool_call_id: event.toolCallId,
      openclaw_run_id: event.runId ?? event.context?.runId,
      openclaw_session_key: event.context?.sessionKey,
      openclaw_session_id: event.context?.sessionId,
      openclaw_job_id: event.context?.jobId,
      reason: stringFrom(event.params.reason) ?? `OpenClaw requested ${event.toolName}`,
    },
  };
}

export function mapGovernedExecParams(params: Record<string, unknown>, config: TanodPluginConfig): TanodToolCallRequest {
  const args: Record<string, unknown> = {};
  if (Array.isArray(params.argv)) args.argv = params.argv.map(String);
  if (typeof params.command === 'string') args.command = params.command;
  return governedRequest('shell.exec', 'infrastructure', 'execute', args, params, config);
}

export function mapGovernedHttpParams(params: Record<string, unknown>, config: TanodPluginConfig): TanodToolCallRequest {
  const args: Record<string, unknown> = { url: params.url, method: params.method ?? 'GET' };
  if (params.headers !== undefined) args.headers = params.headers;
  if (params.body !== undefined) args.body = params.body;
  return governedRequest('http.request', 'network', 'read', args, params, config);
}

export function mapGovernedMcpParams(params: Record<string, unknown>, config: TanodPluginConfig): TanodToolCallRequest {
  const args: Record<string, unknown> = {
    server_url: params.server_url,
    tool_name: params.tool_name,
    tool_arguments: params.tool_arguments ?? {},
  };
  if (params.headers !== undefined) args.headers = params.headers;
  return governedRequest('mcp.call_tool', 'mcp', 'execute', args, params, config);
}

export class TanodClient {
  constructor(private readonly config: TanodPluginConfig) {}

  async decide(request: TanodToolCallRequest): Promise<TanodDecisionResponse> {
    return this.post<TanodDecisionResponse>('/v1/decisions', request, [200]);
  }

  async execute(request: TanodToolCallRequest, approvalToken?: string): Promise<TanodExecutionResponse> {
    return this.post<TanodExecutionResponse>('/v1/executions', { request, approval_token: approvalToken }, [200, 403, 502]);
  }

  async createApprovalRequest(request: TanodToolCallRequest): Promise<TanodApprovalRequestResponse | undefined> {
    try {
      return await this.post<TanodApprovalRequestResponse>('/v1/approval-requests', { request, requested_by: this.config.approvalRequestedBy }, [202, 409]);
    } catch (error) {
      if (!this.config.failClosed) return undefined;
      throw error;
    }
  }

  private async post<T>(path: string, body: unknown, okStatuses: number[]): Promise<T> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.config.apiKey) headers.authorization = `Bearer ${this.config.apiKey}`;
    const response = await fetch(`${this.config.tanodUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) as unknown : {};
    if (!okStatuses.includes(response.status)) {
      const message = parsed && typeof parsed === 'object' && 'error' in parsed ? String((parsed as { error: unknown }).error) : `Tanod returned HTTP ${response.status}`;
      throw new Error(message);
    }
    return parsed as T;
  }
}

export function formatExecutionContent(execution: TanodExecutionResponse, approval?: TanodApprovalRequestResponse): string {
  if (execution.executed) return JSON.stringify(execution.result.output ?? execution.result, null, 2);
  if (execution.decision.decision === 'require_approval') {
    const approvalLine = approval?.approval_id ? ` Approval request: ${approval.approval_id}.` : '';
    return `Tanod blocked execution until approval is granted.${approvalLine} ${execution.result.error ?? execution.decision.message}`.trim();
  }
  return `Tanod ${execution.decision.decision}: ${execution.result.error ?? execution.decision.message}`;
}

function governedRequest(toolName: string, category: string, operation: string, args: Record<string, unknown>, params: Record<string, unknown>, config: TanodPluginConfig): TanodToolCallRequest {
  return {
    version: 'v1',
    request_id: safeId(`oc_governed_${toolName}_${Date.now()}`),
    timestamp: new Date().toISOString(),
    actor: { user_id: stringFrom(params.actorId) ?? config.actorId },
    agent: { agent_id: stringFrom(params.agentId) ?? config.agentId, agent_type: config.agentType, environment: stringFrom(params.agentEnvironment) ?? config.defaultEnvironment },
    tool: { name: toolName, category, operation },
    target: {
      system: stringFrom(params.targetSystem) ?? 'openclaw',
      environment: stringFrom(params.targetEnvironment) ?? config.defaultEnvironment,
      resource: stringFrom(params.targetResource),
    },
    arguments: args,
    context: { reason: stringFrom(params.reason) ?? `OpenClaw requested governed ${toolName}` },
  };
}

function mapToolIdentity(toolName: string, params: Record<string, unknown>): { tool: TanodToolCallRequest['tool']; arguments: Record<string, unknown>; targetSystem?: string; targetResource?: string } {
  const normalized = toolName.toLowerCase();
  if (['exec', 'bash', 'shell', 'code_execution'].includes(normalized)) {
    return { tool: { name: 'shell.exec', category: 'infrastructure', operation: 'execute' }, arguments: params, targetSystem: 'openclaw-host' };
  }
  if (normalized === 'web_fetch') {
    return { tool: { name: 'http.request', category: 'network', operation: 'read' }, arguments: { url: params.url, method: 'GET' }, targetSystem: stringFrom(params.url) };
  }
  if (normalized === 'mcp.call_tool' || normalized === 'mcp_call_tool') {
    return { tool: { name: 'mcp.call_tool', category: 'mcp', operation: 'execute' }, arguments: params, targetSystem: stringFrom(params.server_url) };
  }
  if (['write', 'edit', 'apply_patch'].includes(normalized)) {
    return { tool: { name: `openclaw.${normalized}`, category: 'filesystem', operation: 'write' }, arguments: params, targetSystem: 'openclaw-workspace', targetResource: stringFrom(params.path) };
  }
  return { tool: { name: `openclaw.${normalized}`, category: 'openclaw', operation: 'execute' }, arguments: params };
}

function stringValue(value: unknown, fallback: string | undefined): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback ?? '';
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function stringFrom(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function safeId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.:-]/g, '_').slice(0, 160);
}
