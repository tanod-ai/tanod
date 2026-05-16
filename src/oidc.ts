import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface OidcProviderConfig {
  id: string;
  label?: string;
  issuer: string;
  audience: string;
  clientId?: string;
  jwksUri?: string;
  scope?: string;
}

export interface OidcIdentity {
  provider: string;
  subject: string;
  roles: string[];
  claims: JWTPayload;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
const discoveryCache = new Map<string, Promise<string>>();

export async function verifyOidcToken(token: string, providers: OidcProviderConfig[]): Promise<OidcIdentity | undefined> {
  for (const provider of providers) {
    try {
      const jwks = await getJwks(provider);
      const { payload } = await jwtVerify(token, jwks, {
        issuer: provider.issuer,
        audience: provider.audience,
      });
      return {
        provider: provider.id,
        subject: oidcSubject(payload),
        roles: oidcRoles(payload),
        claims: payload,
      };
    } catch {
      continue;
    }
  }
  return undefined;
}

async function getJwks(provider: OidcProviderConfig): Promise<ReturnType<typeof createRemoteJWKSet>> {
  const uri = provider.jwksUri ?? await discoverJwksUri(provider.issuer);
  const cached = jwksCache.get(uri);
  if (cached) return cached;
  const jwks = createRemoteJWKSet(new URL(uri));
  jwksCache.set(uri, jwks);
  return jwks;
}

async function discoverJwksUri(issuer: string): Promise<string> {
  const normalized = issuer.replace(/\/$/, '');
  let pending = discoveryCache.get(normalized);
  if (!pending) {
    pending = fetch(`${normalized}/.well-known/openid-configuration`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`OIDC discovery failed for ${normalized}: ${response.status}`);
        const metadata = await response.json() as { jwks_uri?: string };
        if (!metadata.jwks_uri) throw new Error(`OIDC discovery for ${normalized} did not include jwks_uri.`);
        return metadata.jwks_uri;
      });
    discoveryCache.set(normalized, pending);
  }
  return pending;
}

function oidcSubject(payload: JWTPayload): string {
  if (!payload.iss || !payload.sub) return String(payload.sub ?? '');
  return `${payload.iss}#${payload.sub}`;
}

function oidcRoles(payload: JWTPayload): string[] {
  const claims = payload as JWTPayload & {
    roles?: unknown;
    groups?: unknown;
    tanod_roles?: unknown;
    realm_access?: { roles?: unknown };
  };
  return [
    ...stringArray(claims.tanod_roles),
    ...stringArray(claims.roles),
    ...stringArray(claims.groups),
    ...stringArray(claims.realm_access?.roles),
  ];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}
