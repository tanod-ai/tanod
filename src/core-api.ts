import type { IncomingMessage, ServerResponse } from 'node:http';

const CORE_API_PATTERNS = [
  /^\/healthz$/,
  /^\/v1\/me$/,
  /^\/v1\/users(?:\/.*)?$/,
  /^\/v1\/invitations(?:\/.*)?$/,
  /^\/v1\/policies(?:\/.*)?$/,
  /^\/v1\/audit-events$/,
  /^\/v1\/agents$/,
  /^\/v1\/decisions$/,
  /^\/v1\/approvals$/,
  /^\/v1\/approval-requests(?:\/.*)?$/,
  /^\/v1\/approval-verifications$/,
  /^\/v1\/executions$/,
];

export function isCoreApiRequest(request: IncomingMessage): boolean {
  const url = new URL(request.url ?? '/', 'http://localhost');
  return CORE_API_PATTERNS.some((pattern) => pattern.test(url.pathname));
}

export async function routeCoreApi(
  request: IncomingMessage,
  response: ServerResponse,
  handler: () => Promise<void>,
): Promise<void> {
  if (!isCoreApiRequest(request)) {
    json(response, 404, { error: 'not found' });
    return;
  }
  await handler();
}

function json(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}
