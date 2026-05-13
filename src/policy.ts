import { readFile } from 'node:fs/promises';
import { hashArguments } from './canonical.js';
import type { DecisionResponse, MatchCondition, PolicyFile, PolicyRule, RiskLevel, ToolCallRequest } from './domain.js';

export async function loadPolicyFile(path: string): Promise<PolicyFile> {
  const raw = await readFile(path, 'utf8');
  const parsed = JSON.parse(raw) as PolicyFile;
  validatePolicyFile(parsed);
  return parsed;
}

export function evaluatePolicy(policyFile: PolicyFile, request: ToolCallRequest): DecisionResponse {
  const policies = [...policyFile.policies].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  const matched = policies.find((policy) => matchesPolicy(policy, request));
  const argumentHash = hashArguments(request.arguments);

  if (!matched) {
    return {
      request_id: request.request_id,
      decision: policyFile.default_decision ?? 'deny',
      risk_level: policyFile.default_risk_level ?? inferRisk(request),
      policy_ids: [],
      argument_hash: argumentHash,
      message: 'No policy matched; default decision applied.',
    };
  }

  return {
    request_id: request.request_id,
    decision: matched.then.decision,
    risk_level: matched.then.risk_level ?? inferRisk(request),
    policy_ids: [matched.id],
    argument_hash: argumentHash,
    message: matched.then.message ?? `Policy ${matched.id} returned ${matched.then.decision}.`,
  };
}

export function matchesPolicy(policy: PolicyRule, request: ToolCallRequest): boolean {
  return Object.entries(policy.when).every(([path, condition]) => matchValue(getPath(request, path), condition));
}

export function inferRisk(request: ToolCallRequest): RiskLevel {
  const env = request.target?.environment ?? request.agent.environment ?? '';
  const op = request.tool.operation ?? '';
  const hint = String(request.tool.risk_hint ?? '').toLowerCase();
  if (hint === 'critical' || hint === 'l4') return 'L4';
  if (hint === 'high' || hint === 'l3') return 'L3';
  if (hint === 'medium' || hint === 'moderate' || hint === 'l2') return 'L2';
  if (hint === 'low' || hint === 'l1') return 'L1';
  if (env === 'prod' && ['delete', 'execute'].includes(op)) return 'L4';
  if (env === 'prod' && op === 'write') return 'L3';
  if (['delete', 'execute'].includes(op)) return 'L3';
  if (op === 'write') return 'L2';
  if (op === 'read') return 'L1';
  return 'L0';
}

function validatePolicyFile(policyFile: PolicyFile): void {
  if (policyFile.version !== 'v1') throw new Error('Policy file version must be v1.');
  if (!Array.isArray(policyFile.policies)) throw new Error('Policy file must contain a policies array.');
  for (const policy of policyFile.policies) {
    if (!policy.id) throw new Error('Policy is missing id.');
    if (!policy.when || typeof policy.when !== 'object') throw new Error(`Policy ${policy.id} is missing when.`);
    if (!policy.then?.decision) throw new Error(`Policy ${policy.id} is missing then.decision.`);
  }
}

function getPath(input: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((current, part) => {
    if (current && typeof current === 'object' && part in current) return (current as Record<string, unknown>)[part];
    return undefined;
  }, input);
}

function matchValue(value: unknown, condition: MatchCondition): boolean {
  if ('equals' in condition) return value === condition.equals;
  if ('contains' in condition) return String(value ?? '').includes(condition.contains);
  if ('contains_any' in condition) {
    const haystack = String(value ?? '');
    return condition.contains_any.some((needle) => haystack.includes(needle));
  }
  if ('matches' in condition) return new RegExp(condition.matches).test(String(value ?? ''));
  if ('in' in condition) return condition.in.some((candidate) => candidate === value);
  return false;
}
