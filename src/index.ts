#!/usr/bin/env node
import { startServer } from './server.js';

const config = {
  host: process.env.TANOD_HOST ?? '0.0.0.0',
  port: Number(process.env.TANOD_PORT ?? '8787'),
  policyFile: process.env.TANOD_POLICY_FILE ?? 'examples/policies/default.json',
  auditFile: process.env.TANOD_AUDIT_FILE ?? '.tanod/audit.jsonl',
  privateKeyFile: process.env.TANOD_PRIVATE_KEY_FILE ?? '.tanod/ed25519-private.pem',
  publicKeyFile: process.env.TANOD_PUBLIC_KEY_FILE ?? '.tanod/ed25519-public.pem',
  enableShellExecution: process.env.TANOD_ENABLE_SHELL_EXECUTION === 'true',
  shellTimeoutMs: Number(process.env.TANOD_SHELL_TIMEOUT_MS ?? '10000'),
  httpTimeoutMs: Number(process.env.TANOD_HTTP_TIMEOUT_MS ?? '10000'),
  apiKeys: (process.env.TANOD_API_KEYS ?? '').split(',').map((key) => key.trim()).filter(Boolean),
  apiKeyRoles: parseApiKeyRoles(process.env.TANOD_API_KEY_ROLES ?? ''),
  apiKeyIdentities: parseApiKeyIdentities(process.env.TANOD_API_KEY_IDENTITIES ?? ''),
};

await startServer(config);

function parseApiKeyRoles(value: string): Record<string, string[]> {
  const roles: Record<string, string[]> = {};
  for (const entry of value.split(';').map((part) => part.trim()).filter(Boolean)) {
    const [key, roleList] = entry.split(':', 2);
    if (!key || !roleList) continue;
    roles[key] = roleList.split(',').map((role) => role.trim()).filter(Boolean);
  }
  return roles;
}

function parseApiKeyIdentities(value: string): Record<string, string> {
  const identities: Record<string, string> = {};
  for (const entry of value.split(';').map((part) => part.trim()).filter(Boolean)) {
    const [key, subject] = entry.split(':', 2);
    if (!key || !subject) continue;
    identities[key] = subject;
  }
  return identities;
}
