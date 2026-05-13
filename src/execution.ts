import { AuditLog } from './audit.js';
import { hashArguments } from './canonical.js';
import type { ApprovalTokenClaims, DecisionResponse, PolicyFile, ToolCallRequest } from './domain.js';
import { evaluatePolicy } from './policy.js';
import { verifyApprovalToken } from './signing.js';
import type { ExecutionResult, ToolAdapter } from './adapters.js';

export interface ExecutionInput {
  request: ToolCallRequest;
  approval_token?: string;
}

export interface ExecutionResponse {
  request_id: string;
  decision: DecisionResponse;
  executed: boolean;
  result: ExecutionResult;
  approval?: Pick<ApprovalTokenClaims, 'approval_id' | 'approved_by' | 'policy_id' | 'tool_args_hash' | 'exp'>;
}

export async function executeGovernedToolCall(params: {
  input: ExecutionInput;
  policyFile: PolicyFile;
  auditLog: AuditLog;
  adapters: Map<string, ToolAdapter>;
  publicKeyPem: string;
}): Promise<ExecutionResponse> {
  const { input, policyFile, auditLog, adapters, publicKeyPem } = params;
  const decision = evaluatePolicy(policyFile, input.request);
  await auditLog.append({
    event_type: 'execution.decision_evaluated',
    request_id: input.request.request_id,
    actor_id: input.request.actor.user_id,
    agent_id: input.request.agent.agent_id,
    tool_name: input.request.tool.name,
    decision: decision.decision,
    risk_level: decision.risk_level,
    policy_ids: decision.policy_ids,
    argument_hash: decision.argument_hash,
  });

  if (decision.decision === 'deny') {
    const result: ExecutionResult = { status: 'blocked', adapter: 'tanod', error: decision.message };
    await auditExecutionResult(auditLog, input.request, decision, result);
    return { request_id: input.request.request_id, decision, executed: false, result };
  }

  let approval: ApprovalTokenClaims | undefined;
  if (decision.decision === 'require_approval') {
    if (!input.approval_token) {
      const result: ExecutionResult = { status: 'blocked', adapter: 'tanod', error: 'Approval token required before execution.' };
      await auditExecutionResult(auditLog, input.request, decision, result);
      return { request_id: input.request.request_id, decision, executed: false, result };
    }
    try {
      approval = verifyApprovalToken(input.approval_token, publicKeyPem, input.request, undefined, {
        policy_id: decision.policy_ids[0],
        required_roles: decision.approval?.required_roles,
      });
    } catch (error) {
      const result: ExecutionResult = { status: 'blocked', adapter: 'tanod', error: error instanceof Error ? error.message : 'Approval token rejected.' };
      await auditExecutionResult(auditLog, input.request, decision, result);
      return { request_id: input.request.request_id, decision, executed: false, result };
    }
    await auditLog.append({
      event_type: 'execution.approval_verified',
      request_id: input.request.request_id,
      actor_id: approval.approved_by,
      agent_id: input.request.agent.agent_id,
      tool_name: input.request.tool.name,
      risk_level: decision.risk_level,
      policy_ids: [approval.policy_id],
      argument_hash: approval.tool_args_hash,
      approval_id: approval.approval_id,
      result: 'success',
    });
  }

  const adapter = adapters.get(input.request.tool.name);
  if (!adapter) {
    const result: ExecutionResult = { status: 'blocked', adapter: 'tanod', error: `No adapter registered for tool ${input.request.tool.name}.` };
    await auditExecutionResult(auditLog, input.request, decision, result);
    return approvalResponse(input.request.request_id, decision, false, result, approval);
  }

  const result = await safelyExecuteAdapter(adapter, input.request);
  await auditExecutionResult(auditLog, input.request, decision, result, approval);
  return approvalResponse(input.request.request_id, decision, result.status === 'success', result, approval);
}

async function safelyExecuteAdapter(adapter: ToolAdapter, request: ToolCallRequest): Promise<ExecutionResult> {
  try {
    return await adapter.execute(request);
  } catch (error) {
    return { status: 'failure', adapter: adapter.name, error: error instanceof Error ? error.message : 'Adapter execution failed.' };
  }
}

function approvalResponse(
  requestId: string,
  decision: DecisionResponse,
  executed: boolean,
  result: ExecutionResult,
  approval?: ApprovalTokenClaims,
): ExecutionResponse {
  return {
    request_id: requestId,
    decision,
    executed,
    result,
    approval: approval
      ? {
          approval_id: approval.approval_id,
          approved_by: approval.approved_by,
          policy_id: approval.policy_id,
          tool_args_hash: approval.tool_args_hash,
          exp: approval.exp,
        }
      : undefined,
  };
}

async function auditExecutionResult(
  auditLog: AuditLog,
  request: ToolCallRequest,
  decision: DecisionResponse,
  result: ExecutionResult,
  approval?: ApprovalTokenClaims,
): Promise<void> {
  await auditLog.append({
    event_type: 'execution.completed',
    request_id: request.request_id,
    actor_id: request.actor.user_id,
    agent_id: request.agent.agent_id,
    tool_name: request.tool.name,
    decision: decision.decision,
    risk_level: decision.risk_level,
    policy_ids: decision.policy_ids,
    argument_hash: hashArguments(request.arguments),
    approval_id: approval?.approval_id,
    result: result.status,
    details: { adapter: result.adapter, error: result.error, metadata: result.metadata },
  });
}
