import { execFile } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
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
  allowPrivateNetworkHttp?: boolean;
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
    const command = parseCommand(request.arguments);
    if (!command.ok) return { status: 'failure', adapter: this.name, error: command.error };

    if (!this.config.enableShellExecution) {
      return {
        status: 'blocked',
        adapter: this.name,
        error: 'Shell execution is disabled. Set TANOD_ENABLE_SHELL_EXECUTION=true to enable it for trusted environments.',
        metadata: { command: command.display },
      };
    }

    try {
      const result = await execFileAsync(command.file, command.args, {
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


function parseCommand(args: Record<string, unknown>): { ok: true; file: string; args: string[]; display: string } | { ok: false; error: string } {
  const argv = args.argv;
  if (argv !== undefined) {
    if (!Array.isArray(argv) || argv.length === 0 || !argv.every((part) => typeof part === 'string' && part.length > 0)) {
      return { ok: false, error: 'shell.exec arguments.argv must be a non-empty string array.' };
    }
    return { ok: true, file: argv[0], args: argv.slice(1), display: argv.join(' ') };
  }

  const command = args.command;
  if (typeof command !== 'string' || command.trim().length === 0) {
    return { ok: false, error: 'shell.exec requires arguments.argv string[] or arguments.command string.' };
  }
  const parsed = parseSimpleCommand(command);
  if (!parsed.ok) return parsed;
  return { ok: true, file: parsed.argv[0], args: parsed.argv.slice(1), display: command };
}

function parseSimpleCommand(command: string): { ok: true; argv: string[] } | { ok: false; error: string } {
  if (/[;&|`$<>(){}\n\r]/.test(command)) {
    return { ok: false, error: 'shell.exec command strings may not contain shell metacharacters; use argv for exact executable arguments.' };
  }
  const argv: string[] = [];
  let current = '';
  let quote: 'single' | 'double' | undefined;
  for (const ch of command.trim()) {
    if (ch === "'" && quote !== 'double') {
      quote = quote === 'single' ? undefined : 'single';
      continue;
    }
    if (ch === '"' && quote !== 'single') {
      quote = quote === 'double' ? undefined : 'double';
      continue;
    }
    if (/\s/.test(ch) && !quote) {
      if (current) {
        argv.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }
  if (quote) return { ok: false, error: 'shell.exec command string has unterminated quote.' };
  if (current) argv.push(current);
  if (argv.length === 0) return { ok: false, error: 'shell.exec command string did not contain an executable.' };
  return { ok: true, argv };
}

interface ValidatedHttpTarget {
  address?: string;
  family?: 4 | 6;
}

async function validateHttpTarget(parsedUrl: URL, allowPrivateNetwork: boolean): Promise<{ ok: true; target: ValidatedHttpTarget } | { ok: false; error: string }> {
  if (allowPrivateNetwork) return { ok: true, target: {} };
  const hostname = parsedUrl.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return { ok: false, error: 'Private HTTP targets are blocked by default.' };
  const literalKind = isIP(hostname);
  if (literalKind !== 0) {
    if (isPrivateAddress(hostname)) return { ok: false, error: 'Private HTTP targets are blocked by default.' };
    return { ok: true, target: { address: hostname, family: literalKind as 4 | 6 } };
  }
  try {
    const addresses = await lookup(hostname, { all: true, verbatim: true });
    if (addresses.length === 0) return { ok: false, error: 'Could not resolve HTTP target.' };
    if (addresses.some((entry) => isPrivateAddress(entry.address))) return { ok: false, error: 'Private HTTP targets are blocked by default.' };
    const selected = addresses[0];
    return { ok: true, target: { address: selected.address, family: selected.family as 4 | 6 } };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Could not resolve HTTP target.' };
  }
}

function isPrivateAddress(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) {
    const [a, b] = address.split('.').map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (kind === 6) {
    const normalized = address.toLowerCase();
    return normalized === '::1' || normalized === '::' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:') || normalized.startsWith('::ffff:127.') || normalized.startsWith('::ffff:10.') || normalized.startsWith('::ffff:192.168.');
  }
  return false;
}

class HttpRequestAdapter implements ToolAdapter {
  readonly name = 'http.request';

  constructor(private readonly config: AdapterConfig) {}

  async execute(request: ToolCallRequest): Promise<ExecutionResult> {
    const url = request.arguments.url;
    const method = String(request.arguments.method ?? 'GET').toUpperCase();
    const body = request.arguments.body;
    const headers = normalizeHeaders(request.arguments.headers);
    if (!headers.ok) return { status: 'failure', adapter: this.name, error: headers.error };

    if (typeof url !== 'string') return { status: 'failure', adapter: this.name, error: 'http.request requires arguments.url string.' };
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method)) {
      return { status: 'failure', adapter: this.name, error: `Unsupported HTTP method: ${method}` };
    }

    return executeHttp(this.name, url, method, headers.value, body, this.config.httpTimeoutMs, this.config.allowPrivateNetworkHttp === true);
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
    if (!headers.ok) return { status: 'failure', adapter: this.name, error: headers.error };

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
        ...(headers.value ?? {}),
      },
      rpcRequest,
      this.config.httpTimeoutMs,
      this.config.allowPrivateNetworkHttp === true,
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
  allowPrivateNetwork: boolean,
): Promise<ExecutionResult> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return { status: 'failure', adapter, error: error instanceof Error ? error.message : 'Invalid URL.' };
  }
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { status: 'failure', adapter, error: `Unsupported URL protocol: ${parsedUrl.protocol}` };
  }
  const networkCheck = await validateHttpTarget(parsedUrl, allowPrivateNetwork);
  if (!networkCheck.ok) return { status: 'blocked', adapter, error: networkCheck.error };

  return executePinnedHttp(adapter, parsedUrl, method, headers, body, timeoutMs, networkCheck.target);
}


function executePinnedHttp(
  adapter: string,
  parsedUrl: URL,
  method: string,
  headers: HeadersInit | undefined,
  body: unknown,
  timeoutMs: number,
  target: ValidatedHttpTarget,
): Promise<ExecutionResult> {
  const client = parsedUrl.protocol === 'https:' ? httpsRequest : httpRequest;
  const requestBody = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  const requestHeaders = headers ? Object.fromEntries(new Headers(headers).entries()) : {};
  return new Promise((resolve) => {
    const req = client(
      parsedUrl,
      {
        method,
        headers: requestHeaders,
        lookup: target.address
          ? (_hostname, _options, callback) => callback(null, target.address!, target.family ?? 4)
          : undefined,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          if (total <= 64 * 1024) chunks.push(Buffer.from(chunk));
          total += chunk.length;
        });
        res.on('end', () => {
          const status = res.statusCode ?? 0;
          const location = res.headers.location;
          if (status >= 300 && status < 400 && location) {
            resolve({ status: 'blocked', adapter, error: 'HTTP redirects are blocked to prevent SSRF bypasses.', metadata: { location } });
            return;
          }
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: status >= 200 && status < 300 ? 'success' : 'failure',
            adapter,
            output: {
              status,
              status_text: res.statusMessage ?? '',
              headers: Object.fromEntries(Object.entries(res.headers).map(([key, value]) => [key, Array.isArray(value) ? value.join(', ') : String(value ?? '')])),
              body: text.slice(0, 64 * 1024),
              truncated: total > 64 * 1024,
            },
          });
        });
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error('HTTP request timed out.')));
    req.on('error', (error) => resolve({ status: 'failure', adapter, error: error.message }));
    if (requestBody !== undefined) req.write(requestBody);
    req.end();
  });
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

function normalizeHeaders(value: unknown): { ok: true; value: Record<string, string> | undefined } | { ok: false; error: string } {
  if (value === undefined) return { ok: true, value: undefined };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { ok: false, error: 'arguments.headers must be an object.' };
  const headers: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value as Record<string, unknown>)) headers[key] = String(headerValue);
  return { ok: true, value: headers };
}
