import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Storage } from './storage.js';
import type { OidcProviderConfig } from './oidc.js';

interface OAuth2ProviderConfig {
  id: string;
  label?: string;
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userUrl: string;
  emailsUrl?: string;
  scope?: string;
}

interface OAuthStateClaims {
  provider: string;
  redirect_uri: string;
  exp: number;
  nonce: string;
}

interface OAuthSessionClaims {
  provider: string;
  identity: string;
  exp: number;
}

class ServerApiError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

export function isServerApiRequest(request: IncomingMessage): boolean {
  const path = (request.url ?? '').split('?', 1)[0];
  return path === '/v1/console-config' || path.startsWith('/v1/oauth2/');
}

const SERVER_AUTHENTICATED_API_PATTERNS = [
  /^\/v1\/me$/,
  /^\/v1\/users(?:\/.*)?$/,
  /^\/v1\/invitations(?:\/.*)?$/,
  /^\/v1\/policies(?:\/.*)?$/,
  /^\/v1\/audit-events$/,
  /^\/v1\/agents$/,
  /^\/v1\/approval-requests(?:\/.*)?$/,
];

export function isServerAuthenticatedApiRequest(request: IncomingMessage): boolean {
  const url = new URL(request.url ?? '/', 'http://localhost');
  return SERVER_AUTHENTICATED_API_PATTERNS.some((pattern) => pattern.test(url.pathname));
}

export async function routeServerAuthenticatedApi(
  request: IncomingMessage,
  response: ServerResponse,
  handler: () => Promise<void>,
): Promise<void> {
  if (!isServerAuthenticatedApiRequest(request)) {
    json(response, 404, { error: 'not found' });
    return;
  }
  await handler();
}

export async function routeServerApi(
  request: IncomingMessage,
  response: ServerResponse,
  config: {
    consoleApiBaseUrl?: string;
    consoleBaseUrl?: string;
    oidcProviders: OidcProviderConfig[];
    oauth2Providers: OAuth2ProviderConfig[];
    oauthSessionSecret: string;
    oauth2CallbackBaseUrl?: string;
    storage: Storage;
  },
): Promise<void> {
  const method = request.method ?? 'GET';
  const path = (request.url ?? '').split('?', 1)[0];

  if (method === 'GET' && path === '/v1/console-config') {
    json(response, 200, {
      api_base_url: config.consoleApiBaseUrl ?? requestApiBaseUrl(request),
      oidc_providers: config.oidcProviders.map((provider) => ({
        id: provider.id,
        label: provider.label ?? providerLabel(provider.id),
        issuer: provider.issuer,
        clientId: provider.clientId ?? provider.audience,
        scope: provider.scope ?? 'openid email profile',
      })),
      oauth2_providers: config.oauth2Providers.map((provider) => ({
        id: provider.id,
        label: provider.label ?? providerLabel(provider.id),
      })),
    });
    return;
  }

  if (method === 'POST' && path === '/v1/oauth2/logout') {
    clearSessionCookie(response);
    json(response, 200, { logged_out: true });
    return;
  }

  if (method === 'GET' && path.startsWith('/v1/oauth2/')) {
    await routeOAuth2(request, response, config.oauth2Providers, config.oauthSessionSecret, config.storage, config.oauth2CallbackBaseUrl, config.consoleBaseUrl);
    return;
  }

  json(response, 404, { error: 'not found' });
}

async function routeOAuth2(request: IncomingMessage, response: ServerResponse, providers: OAuth2ProviderConfig[], secret: string, storage: Storage, callbackBaseUrl?: string, consoleBaseUrl?: string): Promise<void> {
  const url = new URL(request.url ?? '/', requestApiBaseUrl(request));
  const startMatch = url.pathname.match(/^\/v1\/oauth2\/([^/]+)\/start$/);
  if (startMatch) {
    const provider = findOAuth2Provider(providers, decodeURIComponent(startMatch[1]));
    const redirectUri = requireNonEmpty(url.searchParams.get('redirect_uri') ?? undefined, 'redirect_uri');
    validateOAuthRedirectUri(redirectUri, request, consoleBaseUrl);
    const callbackUri = oauth2CallbackUri(request, provider, callbackBaseUrl);
    const state = signEnvelope('tanod-oauth-state', {
      provider: provider.id,
      redirect_uri: redirectUri,
      exp: Math.floor(Date.now() / 1000) + 600,
      nonce: randomBytes(16).toString('hex'),
    } satisfies OAuthStateClaims, secret);
    const params = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: callbackUri,
      scope: provider.scope ?? defaultOAuth2Scope(provider.id),
      state,
    });
    redirect(response, `${provider.authorizationUrl}?${params.toString()}`);
    return;
  }

  const callbackMatch = url.pathname.match(/^\/v1\/oauth2\/([^/]+)\/callback$/);
  if (callbackMatch) {
    const provider = findOAuth2Provider(providers, decodeURIComponent(callbackMatch[1]));
    const code = requireNonEmpty(url.searchParams.get('code') ?? undefined, 'code');
    const claims = verifyEnvelope<OAuthStateClaims>('tanod-oauth-state', requireNonEmpty(url.searchParams.get('state') ?? undefined, 'state'), secret);
    if (claims.provider !== provider.id) throw new ServerApiError(400, 'OAuth2 state provider mismatch.');
    if (claims.exp < Math.floor(Date.now() / 1000)) throw new ServerApiError(400, 'OAuth2 state expired.');
    const callbackUri = oauth2CallbackUri(request, provider, callbackBaseUrl);
    const accessToken = await exchangeOAuth2Code(provider, code, callbackUri);
    const identity = await resolveOAuth2Identity(provider, accessToken);
    if (!identity) throw new ServerApiError(502, 'OAuth2 provider did not return a usable identity.');
    const user = await storage.getUserByIdentity(identity);
    if (!user || user.status !== 'active') {
      const redirectUrl = new URL(claims.redirect_uri);
      redirectUrl.searchParams.set('oauth_error', 'user_not_authorized');
      redirectUrl.searchParams.set('oauth_identity', identity);
      redirect(response, redirectUrl.toString());
      return;
    }
    const sessionToken = signEnvelope('tanod-oauth-session', {
      provider: provider.id,
      identity,
      exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60,
    } satisfies OAuthSessionClaims, secret);
    const redirectUrl = new URL(claims.redirect_uri);
    setSessionCookie(response, sessionToken, cookieOptionsFor(requestApiBaseUrl(request), redirectUrl));
    redirect(response, redirectUrl.toString());
    return;
  }

  throw new ServerApiError(404, 'not found');
}

function findOAuth2Provider(providers: OAuth2ProviderConfig[], id: string): OAuth2ProviderConfig {
  const provider = providers.find((candidate) => candidate.id === id);
  if (!provider) throw new ServerApiError(404, `OAuth2 provider not found: ${id}`);
  return provider;
}

async function exchangeOAuth2Code(provider: OAuth2ProviderConfig, code: string, redirectUri: string): Promise<string> {
  const response = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const token = await response.json() as { access_token?: string; error?: string; error_description?: string };
  if (!response.ok || !token.access_token) throw new ServerApiError(502, token.error_description ?? token.error ?? 'OAuth2 token exchange failed.');
  return token.access_token;
}

async function resolveOAuth2Identity(provider: OAuth2ProviderConfig, accessToken: string): Promise<string> {
  const userResponse = await fetch(provider.userUrl, {
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}`, 'user-agent': 'tanod-core' },
  });
  if (!userResponse.ok) throw new ServerApiError(502, `OAuth2 user lookup failed: ${userResponse.statusText}`);
  const user = await userResponse.json() as { login?: string; email?: string; id?: number | string };
  if (provider.id === 'github' && !user.email && provider.emailsUrl) {
    const email = await resolveGitHubEmail(provider.emailsUrl, accessToken);
    if (email) return email;
  }
  return user.email ?? (user.login ? `github:${user.login}` : undefined) ?? (user.id ? `${provider.id}:${user.id}` : undefined) ?? '';
}

async function resolveGitHubEmail(emailsUrl: string, accessToken: string): Promise<string | undefined> {
  const response = await fetch(emailsUrl, {
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}`, 'user-agent': 'tanod-core' },
  });
  if (!response.ok) return undefined;
  const emails = await response.json() as Array<{ email?: string; primary?: boolean; verified?: boolean }>;
  return emails.find((email) => email.primary && email.verified)?.email ?? emails.find((email) => email.verified)?.email;
}

function defaultOAuth2Scope(id: string): string {
  return id === 'github' ? 'read:user user:email' : 'profile email';
}

function oauth2CallbackUri(request: IncomingMessage, provider: OAuth2ProviderConfig, callbackBaseUrl?: string): string {
  const base = callbackBaseUrl ?? requestApiBaseUrl(request);
  return `${base.replace(/\/$/, '')}/v1/oauth2/${encodeURIComponent(provider.id)}/callback`;
}

function validateOAuthRedirectUri(redirectUri: string, request: IncomingMessage, allowedConsoleBaseUrl?: string): void {
  const redirect = new URL(redirectUri);
  if (redirect.protocol !== 'http:' && redirect.protocol !== 'https:') throw new ServerApiError(400, 'OAuth2 redirect_uri must use http or https.');
  if (allowedConsoleBaseUrl) {
    const allowed = new URL(allowedConsoleBaseUrl);
    if (redirect.origin !== allowed.origin) throw new ServerApiError(400, 'OAuth2 redirect_uri origin is not allowed.');
    return;
  }
  const apiHost = new URL(requestApiBaseUrl(request)).hostname;
  if (redirect.hostname !== apiHost) {
    throw new ServerApiError(400, 'OAuth2 redirect_uri must use the same host as the tanod API.');
  }
}

function setSessionCookie(response: ServerResponse, token: string, options: { sameSite: 'Lax' | 'None'; secure: boolean }): void {
  const parts = [
    `tanod_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    `SameSite=${options.sameSite}`,
    'Max-Age=28800',
  ];
  if (options.secure) parts.push('Secure');
  response.setHeader('set-cookie', parts.join('; '));
}

function clearSessionCookie(response: ServerResponse): void {
  response.setHeader('set-cookie', 'tanod_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

function cookieOptionsFor(apiBaseUrl: string, consoleUrl: URL): { sameSite: 'Lax' | 'None'; secure: boolean } {
  const apiUrl = new URL(apiBaseUrl);
  if (apiUrl.protocol === consoleUrl.protocol && apiUrl.hostname === consoleUrl.hostname) {
    return { sameSite: 'Lax', secure: apiUrl.protocol === 'https:' };
  }
  if (apiUrl.protocol !== 'https:' || consoleUrl.protocol !== 'https:') {
    throw new ServerApiError(400, 'Cross-site OAuth console sessions require HTTPS so tanod can set a SameSite=None; Secure cookie.');
  }
  return { sameSite: 'None', secure: true };
}

function signEnvelope(prefix: string, payload: Record<string, unknown>, secret: string): string {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${prefix}.${encoded}.${signature}`;
}

function verifyEnvelope<T>(prefix: string, token: string, secret: string): T {
  const [actualPrefix, encoded, signature] = token.split('.');
  if (actualPrefix !== prefix || !encoded || !signature) throw new ServerApiError(400, 'Invalid signed token.');
  const expected = createHmac('sha256', secret).update(encoded).digest('base64url');
  if (!constantTimeEqual(signature, expected)) throw new ServerApiError(400, 'Invalid signed token signature.');
  return JSON.parse(Buffer.from(base64urlToBase64(encoded), 'base64').toString('utf8')) as T;
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function base64urlToBase64(value: string): string {
  return value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
}

function providerLabel(id: string): string {
  if (id === 'github') return 'GitHub';
  if (id === 'google') return 'Google';
  if (id === 'microsoft') return 'Microsoft Entra ID';
  return id.replace(/[-_]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function requestApiBaseUrl(request: IncomingMessage): string {
  const host = request.headers.host ?? '127.0.0.1:8787';
  const protoHeader = request.headers['x-forwarded-proto'];
  const proto = Array.isArray(protoHeader) ? protoHeader[0] : protoHeader;
  return `${proto || 'http'}://${host}`;
}

function requireNonEmpty(value: string | undefined, field: string): string {
  if (!value?.trim()) throw new ServerApiError(400, `${field} is required.`);
  return value.trim();
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(302, { location });
  response.end();
}

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
