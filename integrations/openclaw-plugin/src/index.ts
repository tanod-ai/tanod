import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import {
  TanodClient,
  formatExecutionContent,
  isProtectedTool,
  mapGovernedExecParams,
  mapGovernedHttpParams,
  mapGovernedMcpParams,
  mapOpenClawToolCallToTanod,
  normalizeConfig,
  waitForTanodApproval,
  type OpenClawToolEvent,
  type TanodPluginConfig,
  type TanodToolCallRequest,
} from './tanod.js';

const TOOL_RESULT_PREFIX = '[Tanod]';

export default definePluginEntry({
  id: 'tanod',
  name: 'Tanod',
  description: 'Injects Tanod signed execution control into OpenClaw tool calls.',
  register(api: any) {
    const pluginConfig = api.pluginConfig;
    api.on(
      'before_tool_call',
      async (event: OpenClawToolEvent) => beforeToolCall(event, pluginConfig),
      { priority: 10_000, timeoutMs: 600_000 },
    );

    api.registerTool(
      {
        name: 'tanod_exec',
        description: 'Execute a shell command through Tanod policy, approval, signed execution, and audit.',
        parameters: objectSchema({
          argv: { type: 'array', items: { type: 'string' }, description: 'Preferred executable argv, e.g. ["ls", "-la"].' },
          command: { type: 'string', description: 'Legacy simple command string. argv is preferred.' },
          approvalToken: { type: 'string', description: 'Optional Tanod approval token for retrying an approved action.' },
          targetSystem: { type: 'string' },
          targetEnvironment: { type: 'string' },
          targetResource: { type: 'string' },
          reason: { type: 'string' },
        }),
        async execute(_id: string, params: Record<string, unknown>) {
          return governedToolResult(mapGovernedExecParams(params, normalizeConfig(pluginConfig)), params, pluginConfig);
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: 'tanod_http_request',
        description: 'Make an HTTP request through Tanod policy, approval, signed execution, SSRF checks, and audit.',
        parameters: objectSchema({
          url: { type: 'string' },
          method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] },
          headers: { type: 'object', additionalProperties: { type: 'string' } },
          body: {},
          approvalToken: { type: 'string' },
          targetSystem: { type: 'string' },
          targetEnvironment: { type: 'string' },
          targetResource: { type: 'string' },
          reason: { type: 'string' },
        }, ['url']),
        async execute(_id: string, params: Record<string, unknown>) {
          return governedToolResult(mapGovernedHttpParams(params, normalizeConfig(pluginConfig)), params, pluginConfig);
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: 'tanod_mcp_call_tool',
        description: 'Call an MCP tool through Tanod policy, approval, signed execution, and audit.',
        parameters: objectSchema({
          server_url: { type: 'string' },
          tool_name: { type: 'string' },
          tool_arguments: { type: 'object' },
          headers: { type: 'object', additionalProperties: { type: 'string' } },
          approvalToken: { type: 'string' },
          targetSystem: { type: 'string' },
          targetEnvironment: { type: 'string' },
          targetResource: { type: 'string' },
          reason: { type: 'string' },
        }, ['server_url', 'tool_name']),
        async execute(_id: string, params: Record<string, unknown>) {
          return governedToolResult(mapGovernedMcpParams(params, normalizeConfig(pluginConfig)), params, pluginConfig);
        },
      },
      { optional: true },
    );
  },
});

async function beforeToolCall(event: OpenClawToolEvent, pluginConfig?: unknown): Promise<Record<string, unknown> | undefined> {
  const config = configFromEvent(event, pluginConfig);
  const protectedTool = isProtectedTool(event.toolName, config);
  if (event.toolName.startsWith('tanod_')) return undefined;

  if (config.mode === 'governed_replacement') {
    if (protectedTool && config.blockRawProtectedToolsInGovernedMode) {
      return {
        block: true,
        blockReason: `Blocked by Tanod: raw OpenClaw tool '${event.toolName}' is protected. Use tanod_exec, tanod_http_request, or tanod_mcp_call_tool instead.`,
      };
    }
    return undefined;
  }

  if (!protectedTool) return undefined;

  const client = new TanodClient(config);
  const request = mapOpenClawToolCallToTanod(event, config);
  try {
    const decision = await client.decide(request);
    if (decision.decision === 'allow') return undefined;
    if (decision.decision === 'deny') {
      return { block: true, blockReason: decision.message || 'Blocked by Tanod policy.' };
    }

    if (!config.createApprovalRequests) {
      return { block: true, blockReason: `${decision.message} Tanod approval is required, but approval request creation is disabled.` };
    }
    const approval = await client.createApprovalRequest(request);
    if (!approval?.approval_id) return { block: true, blockReason: 'Tanod approval is required, but no approval request was created.' };
    const waited = await waitForTanodApproval(client, approval.approval_id, config);
    if (waited.status !== 'approved') return { block: true, blockReason: waited.reason };
    await client.verifyApproval(request, waited.approvalToken);
    return undefined;
  } catch (error) {
    if (config.failClosed) {
      return { block: true, blockReason: `Tanod unavailable or rejected request: ${error instanceof Error ? error.message : 'unknown error'}` };
    }
    return undefined;
  }
}

async function governedToolResult(request: TanodToolCallRequest, params: Record<string, unknown>, pluginConfig?: unknown): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const config = normalizeConfig(pluginConfig);
  const client = new TanodClient(config);
  const approvalToken = typeof params.approvalToken === 'string' ? params.approvalToken : undefined;
  const execution = await client.execute(request, approvalToken);
  if (execution.executed || execution.decision.decision !== 'require_approval') {
    return { content: [{ type: 'text', text: `${TOOL_RESULT_PREFIX} ${formatExecutionContent(execution)}` }] };
  }
  if (!config.createApprovalRequests) {
    return { content: [{ type: 'text', text: `${TOOL_RESULT_PREFIX} ${formatExecutionContent(execution)} Approval request creation is disabled.` }] };
  }
  const approval = await client.createApprovalRequest(request);
  if (!approval?.approval_id) {
    return { content: [{ type: 'text', text: `${TOOL_RESULT_PREFIX} ${formatExecutionContent(execution)} No approval request was created.` }] };
  }
  const waited = await waitForTanodApproval(client, approval.approval_id, config);
  if (waited.status !== 'approved') {
    return { content: [{ type: 'text', text: `${TOOL_RESULT_PREFIX} ${waited.reason}` }] };
  }
  const approvedExecution = await client.execute(request, waited.approvalToken);
  return { content: [{ type: 'text', text: `${TOOL_RESULT_PREFIX} ${formatExecutionContent(approvedExecution, waited)}` }] };
}

function configFromEvent(event: OpenClawToolEvent, pluginConfig?: unknown): TanodPluginConfig {
  return normalizeConfig(event.context?.pluginConfig ?? pluginConfig);
}

function objectSchema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return { type: 'object', additionalProperties: false, properties, required };
}

function severityForRisk(risk: string): 'info' | 'warning' | 'critical' {
  if (risk === 'L4' || risk === 'L3') return 'critical';
  if (risk === 'L2') return 'warning';
  return 'info';
}
