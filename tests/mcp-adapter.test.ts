import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { createAdapterRegistry } from '../src/adapters.js';
import type { ToolCallRequest } from '../src/domain.js';

test('mcp.call_tool sends MCP tools/call JSON-RPC request', async () => {
  const received: unknown[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    received.push(body);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: 'pong' }] } }));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    assert.equal(typeof address, 'object');
    const port = (address as { port: number }).port;
    const request: ToolCallRequest = {
      version: 'v1',
      request_id: 'req_mcp_test',
      actor: { user_id: 'ross@example.com' },
      agent: { agent_id: 'dev-agent', environment: 'dev' },
      tool: { name: 'mcp.call_tool', category: 'mcp', operation: 'execute' },
      target: { system: 'test-mcp', environment: 'dev' },
      arguments: {
        server_url: `http://127.0.0.1:${port}/mcp`,
        tool_name: 'echo',
        tool_arguments: { message: 'ping' },
      },
    };

    const adapter = createAdapterRegistry({ enableShellExecution: false, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }).get('mcp.call_tool');
    assert.ok(adapter);
    const result = await adapter.execute(request);
    assert.equal(result.status, 'success');
    assert.deepEqual(received, [
      {
        jsonrpc: '2.0',
        id: 'req_mcp_test',
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'ping' } },
      },
    ]);
    assert.deepEqual(result.output, { content: [{ type: 'text', text: 'pong' }] });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});

test('mcp.call_tool reports JSON-RPC errors as failures', async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: 'req_mcp_error', error: { code: -32601, message: 'tool not found' } }));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    assert.equal(typeof address, 'object');
    const port = (address as { port: number }).port;
    const request: ToolCallRequest = {
      version: 'v1',
      request_id: 'req_mcp_error',
      actor: { user_id: 'ross@example.com' },
      agent: { agent_id: 'dev-agent', environment: 'dev' },
      tool: { name: 'mcp.call_tool', category: 'mcp', operation: 'execute' },
      target: { system: 'test-mcp', environment: 'dev' },
      arguments: { server_url: `http://127.0.0.1:${port}/mcp`, tool_name: 'missing', tool_arguments: {} },
    };

    const adapter = createAdapterRegistry({ enableShellExecution: false, shellTimeoutMs: 1000, httpTimeoutMs: 1000 }).get('mcp.call_tool');
    assert.ok(adapter);
    const result = await adapter.execute(request);
    assert.equal(result.status, 'failure');
    assert.equal(result.error, 'tool not found');
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});
