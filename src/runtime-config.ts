import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface TanodRuntimeConfig {
  base_url?: string;
  api_key?: string;
  oidc_providers?: Array<{
    id: string;
    label?: string;
    issuer: string;
    audience?: string;
    client_id?: string;
    jwks_uri?: string;
    scope?: string;
  }>;
  oauth2_providers?: Array<{
    id: string;
    label?: string;
    client_id: string;
    client_secret: string;
    authorization_url: string;
    token_url: string;
    user_url: string;
    emails_url?: string;
    scope?: string;
  }>;
}

export function tanodConfigPath(env = process.env): string {
  if (env.TANOD_CONFIG_FILE) return env.TANOD_CONFIG_FILE;
  const configHome = env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(configHome, 'tanod', 'config.json');
}

export async function loadTanodRuntimeConfig(env = process.env): Promise<TanodRuntimeConfig> {
  try {
    const raw = await readFile(tanodConfigPath(env), 'utf8');
    const parsed = JSON.parse(raw) as TanodRuntimeConfig;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw error;
  }
}
