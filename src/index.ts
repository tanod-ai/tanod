#!/usr/bin/env node
import { startServer } from './server.js';
import { loadTanodRuntimeConfig } from './runtime-config.js';

const host = process.env.TANOD_HOST ?? '127.0.0.1';
const runtimeConfig = await loadTanodRuntimeConfig();
const apiKeys = (process.env.TANOD_API_KEYS ?? '').split(',').map((key) => key.trim()).filter(Boolean);
const oidcProviders = mergeOidcProviders(
  parseConfiguredOidcProviders(runtimeConfig.oidc_providers ?? []),
  parseOidcProviders(process.env.TANOD_OIDC_PROVIDERS ?? ''),
);
const oauth2Providers = parseConfiguredOAuth2Providers(runtimeConfig.oauth2_providers ?? []);
if (!isLoopbackHost(host) && apiKeys.length === 0 && process.env.TANOD_ALLOW_UNAUTHENTICATED !== 'true') {
  throw new Error('Refusing to bind tanod-core to a non-loopback host without TANOD_API_KEYS. OAuth/OIDC protects browser login, but tanod-core machine APIs for the CLI and OpenClaw require API-key authentication. Configure TANOD_API_KEYS or explicitly set TANOD_ALLOW_UNAUTHENTICATED=true for isolated development.');
}

const config = {
  host,
  port: Number(process.env.TANOD_PORT ?? '8787'),
  policyFile: process.env.TANOD_POLICY_FILE ?? 'examples/policies/default.json',
  auditFile: process.env.TANOD_AUDIT_FILE ?? '.tanod/audit.jsonl',
  privateKeyFile: process.env.TANOD_PRIVATE_KEY_FILE ?? '.tanod/ed25519-private.pem',
  publicKeyFile: process.env.TANOD_PUBLIC_KEY_FILE ?? '.tanod/ed25519-public.pem',
  enableShellExecution: process.env.TANOD_ENABLE_SHELL_EXECUTION === 'true',
  shellTimeoutMs: Number(process.env.TANOD_SHELL_TIMEOUT_MS ?? '10000'),
  httpTimeoutMs: Number(process.env.TANOD_HTTP_TIMEOUT_MS ?? '10000'),
  allowPrivateNetworkHttp: process.env.TANOD_ALLOW_PRIVATE_NETWORK_HTTP === 'true',
  apiKeys,
  allowUnauthenticated: process.env.TANOD_ALLOW_UNAUTHENTICATED === 'true',
  apiKeyRoles: parseApiKeyRoles(process.env.TANOD_API_KEY_ROLES ?? ''),
  apiKeyIdentities: parseApiKeyIdentities(process.env.TANOD_API_KEY_IDENTITIES ?? ''),
  oidcProviders,
  oauth2Providers,
  oidcIdentityRoles: parseIdentityRoles(process.env.TANOD_OIDC_IDENTITY_ROLES ?? ''),
  bootstrapAdmins: parseList(process.env.TANOD_BOOTSTRAP_ADMINS ?? ''),
  consoleBaseUrl: process.env.TANOD_CONSOLE_BASE_URL,
  consoleApiBaseUrl: runtimeConfig.base_url ?? process.env.TANOD_CONSOLE_API_BASE_URL,
  oauth2CallbackBaseUrl: normalizeOptionalBaseUrl(process.env.TANOD_OAUTH_CALLBACK_BASE_URL ?? runtimeConfig.base_url ?? process.env.TANOD_CONSOLE_API_BASE_URL),
  invitationTtlDays: Number(process.env.TANOD_INVITATION_TTL_DAYS ?? '7'),
  invitationEmailWebhook: process.env.TANOD_INVITE_EMAIL_WEBHOOK,
};

await startServer(config);

function isLoopbackHost(value: string): boolean {
  return ['127.0.0.1', 'localhost', '::1'].includes(value);
}

function parseApiKeyRoles(value: string): Record<string, string[]> {
  const roles: Record<string, string[]> = {};
  for (const entry of value.split(';').map((part) => part.trim()).filter(Boolean)) {
    const [key, roleList] = entry.split(':', 2);
    if (!key || !roleList) continue;
    roles[key] = roleList.split(',').map((role) => role.trim()).filter(Boolean);
  }
  return roles;
}

function normalizeOptionalBaseUrl(value?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  const url = new URL(trimmed);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('TANOD_OAUTH_CALLBACK_BASE_URL must use http or https.');
  }
  url.pathname = url.pathname.replace(/\/$/, '');
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
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

function parseOidcProviders(value: string): Array<{ id: string; label?: string; issuer: string; audience: string; clientId?: string; jwksUri?: string; scope?: string }> {
  return value.split(';').map((part) => part.trim()).filter(Boolean).map((entry) => {
    const [id, issuer, audience, jwksUri, clientId, label] = entry.split('|').map((field) => field.trim());
    if (!id || !issuer || !audience) {
      throw new Error('TANOD_OIDC_PROVIDERS entries must be id|issuer|audience[|jwks_uri|client_id|label].');
    }
    return { id, label: label || undefined, issuer: issuer.replace(/\/$/, ''), audience, clientId: clientId || audience, jwksUri: jwksUri || undefined };
  });
}

function parseConfiguredOidcProviders(providers: NonNullable<typeof runtimeConfig.oidc_providers>): Array<{ id: string; label?: string; issuer: string; audience: string; clientId?: string; jwksUri?: string; scope?: string }> {
  return providers.map((provider) => {
    const audience = provider.audience ?? provider.client_id;
    if (!provider.id || !provider.issuer || !audience) {
      throw new Error('tanod config oidc_providers entries must include id, issuer, and audience or client_id.');
    }
    return {
      id: provider.id,
      label: provider.label,
      issuer: provider.issuer.replace(/\/$/, ''),
      audience,
      clientId: provider.client_id ?? audience,
      jwksUri: provider.jwks_uri,
      scope: provider.scope,
    };
  });
}

function mergeOidcProviders(...groups: Array<Array<{ id: string; label?: string; issuer: string; audience: string; clientId?: string; jwksUri?: string; scope?: string }>>): Array<{ id: string; label?: string; issuer: string; audience: string; clientId?: string; jwksUri?: string; scope?: string }> {
  const merged = new Map<string, { id: string; label?: string; issuer: string; audience: string; clientId?: string; jwksUri?: string; scope?: string }>();
  for (const group of groups) {
    for (const provider of group) merged.set(provider.id, provider);
  }
  return [...merged.values()];
}

function parseConfiguredOAuth2Providers(providers: NonNullable<typeof runtimeConfig.oauth2_providers>): Array<{ id: string; label?: string; clientId: string; clientSecret: string; authorizationUrl: string; tokenUrl: string; userUrl: string; emailsUrl?: string; scope?: string }> {
  return providers.map((provider) => {
    if (!provider.id || !provider.client_id || !provider.client_secret || !provider.authorization_url || !provider.token_url || !provider.user_url) {
      throw new Error('tanod config oauth2_providers entries must include id, client_id, client_secret, authorization_url, token_url, and user_url.');
    }
    return {
      id: provider.id,
      label: provider.label,
      clientId: provider.client_id,
      clientSecret: provider.client_secret,
      authorizationUrl: provider.authorization_url,
      tokenUrl: provider.token_url,
      userUrl: provider.user_url,
      emailsUrl: provider.emails_url,
      scope: provider.scope,
    };
  });
}

function parseIdentityRoles(value: string): Record<string, string[]> {
  const roles: Record<string, string[]> = {};
  for (const entry of value.split(';').map((part) => part.trim()).filter(Boolean)) {
    const [identity, roleList] = entry.split(':', 2);
    if (!identity || !roleList) continue;
    roles[identity] = roleList.split(',').map((role) => role.trim()).filter(Boolean);
  }
  return roles;
}

function parseList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}
