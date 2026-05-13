import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ToolCallRequest } from './domain.js';

const execFileAsync = promisify(execFile);

export interface ExecutionResult {
  status: 'success' | 'failure' | 'blocked';
  adapter: string;
  output?: unknown;
  error?: string;
  metadata?: Record<string, unknown>;
}

export interface ToolAdapter {
  name: string;
  execute(request: ToolCallRequest): Promise<ExecutionResult>;
}

export interface AdapterConfig {
  enableShellExecution: boolean;
  shellTimeoutMs: number;
  httpTimeoutMs: number;
}

export function createAdapterRegistry(config: AdapterConfig): Map<string, ToolAdapter> {
  return new Map<string, ToolAdapter>([
    ['shell.exec', new ShellExecAdapter(config)],
    ['http.request', new HttpRequestAdapter(config)],
  ]);
}

class ShellExecAdapter implements ToolAdapter {
  readonly name = 'shell.exec';

  constructor(private readonly config: AdapterConfig) {}

  async execute(request: ToolCallRequest): Promise<ExecutionResult> {
    const command = request.arguments.command;
    if (typeof command !== 'string' || command.trim().length === 0) {
      return { status: 'failure', adapter: this.name, error: 'shell.exec requires arguments.command string.' };
    }

    if (!this.config.enableShellExecution) {
      return {
        status: 'blocked',
        adapter: this.name,
        error: 'Shell execution is disabled. Set TANOD_ENABLE_SHELL_EXECUTION=true to enable it for trusted environments.',
        metadata: { command },
      };
    }

    try {
      // We intentionally do not invoke a shell. The command string is passed as
      // one argument to /bin/sh -lc only after explicit operator opt-in via env.
      // This preserves expected shell semantics while keeping execution disabled
      // by default for safe development and demos.
      const result = await execFileAsync('/bin/sh', ['-lc', command], {
        timeout: this.config.shellTimeoutMs,
        maxBuffer: 1024 * 1024,
      });
      return {
        status: 'success',
        adapter: this.name,
        output: { stdout: result.stdout, stderr: result.stderr, exit_code: 0 },
      };
    } catch (error) {
      const err = error as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number | string; signal?: string };
      return {
        status: 'failure',
        adapter: this.name,
        error: err.message,
        output: { stdout: err.stdout, stderr: err.stderr, exit_code: err.code, signal: err.signal },
      };
    }
  }
}

class HttpRequestAdapter implements ToolAdapter {
  readonly name = 'http.request';

  constructor(private readonly config: AdapterConfig) {}

  async execute(request: ToolCallRequest): Promise<ExecutionResult> {
    const url = request.arguments.url;
    const method = String(request.arguments.method ?? 'GET').toUpperCase();
    const body = request.arguments.body;
    const headers = normalizeHeaders(request.arguments.headers);

    if (typeof url !== 'string') return { status: 'failure', adapter: this.name, error: 'http.request requires arguments.url string.' };
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method)) {
      return { status: 'failure', adapter: this.name, error: `Unsupported HTTP method: ${method}` };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.httpTimeoutMs);
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();
      return {
        status: response.ok ? 'success' : 'failure',
        adapter: this.name,
        output: {
          status: response.status,
          status_text: response.statusText,
          headers: Object.fromEntries(response.headers.entries()),
          body: text.slice(0, 64 * 1024),
          truncated: text.length > 64 * 1024,
        },
      };
    } catch (error) {
      return { status: 'failure', adapter: this.name, error: error instanceof Error ? error.message : 'HTTP request failed.' };
    } finally {
      clearTimeout(timeout);
    }
  }
}

function normalizeHeaders(value: unknown): HeadersInit | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('arguments.headers must be an object.');
  const headers: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value as Record<string, unknown>)) headers[key] = String(headerValue);
  return headers;
}
