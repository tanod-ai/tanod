import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { canonicalize, hashArguments, sha256Hex } from './canonical.js';
import type { ApprovalTokenClaims, RiskLevel, ToolCallRequest } from './domain.js';

export interface KeyPairPem {
  privateKeyPem: string;
  publicKeyPem: string;
}

export const DEFAULT_APPROVAL_TTL_SECONDS = 900;
export const MAX_APPROVAL_TTL_SECONDS = 3600;

export interface ApprovalInput {
  request: ToolCallRequest;
  approved_by: string;
  approved_role?: string;
  policy_id: string;
  risk_level: RiskLevel;
  ttl_seconds?: number;
  approval_id?: string;
}

export interface ApprovalVerificationRequirements {
  policy_id?: string;
  required_roles?: string[];
}

export function generateSigningKeyPair(): KeyPairPem {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function signApproval(input: ApprovalInput, privateKeyPem: string): { token: string; claims: ApprovalTokenClaims } {
  const now = Math.floor(Date.now() / 1000);
  const ttl = normalizeApprovalTtl(input.ttl_seconds);
  const claims: ApprovalTokenClaims = {
    iss: 'tanod',
    sub: 'approval',
    aud: 'tanod-tool-proxy',
    approval_id: input.approval_id ?? `appr_${randomUUID()}`,
    approved_by: input.approved_by,
    approved_role: input.approved_role,
    request_id: input.request.request_id,
    actor_id: input.request.actor.user_id,
    agent_id: input.request.agent.agent_id,
    tool_name: input.request.tool.name,
    tool_operation: input.request.tool.operation,
    target_system: input.request.target?.system,
    target_environment: input.request.target?.environment,
    target_resource: input.request.target?.resource,
    tool_args_hash: hashArguments(input.request.arguments),
    tool_call_hash: hashToolCall(input.request),
    risk_level: input.risk_level,
    policy_id: input.policy_id,
    decision: 'approved',
    iat: now,
    exp: now + ttl,
  };

  const header = { alg: 'EdDSA', typ: 'tanod-approval+jws' };
  const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;
  const signature = sign(null, Buffer.from(signingInput), createPrivateKey(privateKeyPem));
  return { token: `${signingInput}.${base64url(signature)}`, claims };
}

export function verifyApprovalToken(
  token: string,
  publicKeyPem: string,
  request?: ToolCallRequest,
  nowSeconds = Math.floor(Date.now() / 1000),
  requirements: ApprovalVerificationRequirements = {},
): ApprovalTokenClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Approval token must have three compact JWS parts.');
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const ok = verify(
    null,
    Buffer.from(signingInput),
    createPublicKey(publicKeyPem),
    Buffer.from(base64urlDecode(encodedSignature)),
  );
  if (!ok) throw new Error('Approval token signature is invalid.');

  const claims = JSON.parse(Buffer.from(base64urlDecode(encodedClaims)).toString('utf8')) as ApprovalTokenClaims;
  if (claims.iss !== 'tanod' || claims.sub !== 'approval' || claims.aud !== 'tanod-tool-proxy') {
    throw new Error('Approval token has invalid issuer, subject, or audience.');
  }
  if (claims.exp <= nowSeconds) throw new Error('Approval token has expired.');
  if (request) {
    const actualHash = hashArguments(request.arguments);
    if (claims.request_id !== request.request_id) throw new Error('Approval token request_id does not match request.');
    if (claims.actor_id !== request.actor.user_id) throw new Error('Approval token actor does not match request.');
    if (claims.agent_id !== request.agent.agent_id) throw new Error('Approval token agent does not match request.');
    if (claims.tool_name !== request.tool.name) throw new Error('Approval token tool does not match request.');
    if (claims.tool_operation !== request.tool.operation) throw new Error('Approval token tool operation does not match request.');
    if (claims.target_system !== request.target?.system) throw new Error('Approval token target system does not match request.');
    if (claims.target_environment !== request.target?.environment) throw new Error('Approval token target environment does not match request.');
    if (claims.target_resource !== request.target?.resource) throw new Error('Approval token target resource does not match request.');
    if (claims.tool_args_hash !== actualHash) throw new Error('Approval token argument hash does not match request.');
    if (claims.tool_call_hash !== hashToolCall(request)) throw new Error('Approval token full action hash does not match request.');
  }
  if (requirements.policy_id && claims.policy_id !== requirements.policy_id) {
    throw new Error('Approval token policy does not match required policy.');
  }
  const requiredRoles = requirements.required_roles ?? [];
  const hasRbacApprovalRole = claims.approved_role === 'Admin' || claims.approved_role === 'Approver';
  if (requiredRoles.length > 0 && !hasRbacApprovalRole && (!claims.approved_role || !requiredRoles.includes(claims.approved_role))) {
    throw new Error('Approval token approved_role is not authorized for this policy.');
  }
  return claims;
}

export function normalizeApprovalTtl(ttlSeconds: number | undefined, maxSeconds = MAX_APPROVAL_TTL_SECONDS): number {
  const ttl = ttlSeconds ?? DEFAULT_APPROVAL_TTL_SECONDS;
  if (!Number.isInteger(ttl) || ttl < 1) throw new Error('Approval token ttl_seconds must be a positive integer.');
  if (ttl > maxSeconds) throw new Error(`Approval token ttl_seconds must be <= ${maxSeconds}.`);
  return ttl;
}

export function hashToolCall(request: ToolCallRequest): string {
  return `sha256:${sha256Hex(canonicalize(request))}`;
}

function base64urlJson(value: unknown): string {
  return base64url(Buffer.from(JSON.stringify(value)));
}

function base64url(input: Buffer): string {
  return input.toString('base64url');
}

function base64urlDecode(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}
