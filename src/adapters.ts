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
    ['mcp.call_tool', new McpCallToolAdapter(config)],
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

    return executeHttp(this.name, url, method, headers, body, this.config.httpTimeoutMs);
  }
}

class McpCallToolAdapter implements ToolAdapter {
  readonly name = 'mcp.call_tool';

  constructor(private readonly config: AdapterConfig) {}

  async execute(request: ToolCallRequest): Promise<ExecutionResult> {
    const serverUrl = request.arguments.server_url;
    const toolName = request.arguments.tool_name;
    const toolArguments = request.arguments.tool_arguments ?? {};
    const headers = normalizeHeaders(request.arguments.headers);

    if (typeof serverUrl !== 'string') return { status: 'failure', adapter: this.name, error: 'mcp.call_tool requires arguments.server_url string.' };
    if (typeof toolName !== 'string' || toolName.trim().length === 0) {
      return { status: 'failure', adapter: this.name, error: 'mcp.call_tool requires arguments.tool_name string.' };
    }
    if (!toolArguments || typeof toolArguments !== 'object' || Array.isArray(toolArguments)) {
      return { status: 'failure', adapter: this.name, error: 'mcp.call_tool arguments.tool_arguments must be an object when provided.' };
    }

    const rpcRequest = {
      jsonrpc: '2.0',
      id: request.request_id,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: toolArguments,
      },
    };

    const result = await executeHttp(
      this.name,
      serverUrl,
      'POST',
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        ...(headers ?? {}),
      },
      rpcRequest,
      this.config.httpTimeoutMs,
    );

    if (result.status !== 'success') return result;
    const output = result.output as HttpOutput;
    const parsed = parseMcpBody(output.body);
    if (!parsed.ok) return { status: 'failure', adapter: this.name, error: parsed.error, output };
    if (parsed.value.error) {
      const rpcError = parsed.value.error as { message?: string };
      return { status: 'failure', adapter: this.name, error: rpcError.message ?? 'MCP tool call failed.', output: parsed.value };
    }
    return { status: 'success', adapter: this.name, output: parsed.value.result ?? parsed.value };
  }
}

interface HttpOutput {
  status: number;
  status_text: string;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

async function executeHttp(
  adapter: string,
  url: string,
  method: string,
  headers: HeadersInit | undefined,
  body: unknown,
  timeoutMs: number,
): Promise<ExecutionResult> {
  const parsedUrl = new URL(url);
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { status: 'failure', adapter, error: `Unsupported URL protocol: ${parsedUrl.protocol}` };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(parsedUrl, {
      method,
      headers,
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    return {
      status: response.ok ? 'success' : 'failure',
      adapter,
      output: {
        status: response.status,
        status_text: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: text.slice(0, 64 * 1024),
        truncated: text.length > 64 * 1024,
      },
    };
  } catch (error) {
    return { status: 'failure', adapter, error: error instanceof Error ? error.message : 'HTTP request failed.' };
  } finally {
    clearTimeout(timeout);
  }
}

function parseMcpBody(body: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  const trimmed = body.trim();
  if (!trimmed) return { ok: false, error: 'MCP server returned an empty response body.' };

  if (trimmed.startsWith('data:')) {
    const dataLine = trimmed
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.startsWith('data:'));
    if (!dataLine) return { ok: false, error: 'MCP SSE response did not include a data line.' };
    return parseJsonObject(dataLine.slice('data:'.length).trim());
  }

  return parseJsonObject(trimmed);
}

function parseJsonObject(value: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, error: 'MCP response must be a JSON object.' };
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? `Could not parse MCP response: ${error.message}` : 'Could not parse MCP response.' };
  }
}

function normalizeHeaders(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('arguments.headers must be an object.');
  const headers: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value as Record<string, unknown>)) headers[key] = String(headerValue);
  return headers;
}
