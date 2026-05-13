# Tanod

**Open-source signed execution control for AI agents.**

Tanod is a security control plane that sits between AI agents and the tools they use. It intercepts tool calls before execution, evaluates them against deterministic policy, requires human approval for high-risk actions, cryptographically binds approvals to the exact requested action, and records decisions in an auditable trail.

AI agents should not be able to grant admin access, delete data, deploy to production, send sensitive information, or run destructive commands just because a model decided to call a tool.

Tanod separates **reasoning** from **execution**.

```text
AI Agent → Tanod Gateway → Policy → Approval → Signed Execution → Audit → Tool
```

## Project status

Tanod is in early v0.1 development. The current repository contains the first executable gateway skeleton:

- HTTP API for evaluating and executing governed agent tool-call requests
- Deterministic policy engine with allow / deny / require-approval decisions
- Risk levels from L0 to L4
- Canonical argument hashing
- Ed25519 signed approval tokens bound to exact tool-call arguments
- Tamper-evident append-only audit log primitive
- Postgres-backed storage for tool calls, approvals, and audit events
- Persistent approval request queue with approve/reject lifecycle
- `tanodctl` CLI for decisions, approvals, execution, and audit verification
- Dockerfile and Docker Compose deployment with Postgres
- Built-in `/console` approval UI for pending approvals
- Optional API-key authentication via `TANOD_API_KEYS`
- Example policies and tool-call requests
- Node test suite for policy, signing, guarded execution, adapters, and audit behavior

The implementation is currently TypeScript/Node.js because this build environment has Node available but not Go. The architecture is intentionally modular so core services can later be split, rewritten, or complemented by Go/Rust components where appropriate.

## Why Tanod exists

Traditional automation mostly failed by following the wrong process or receiving bad inputs. AI agents introduce a different risk: they can confidently misunderstand intent and then take real action.

Prompt guardrails are not enough. The dangerous boundary is not just what the model says; it is what the agent tries to **do**.

Tanod focuses on the execution boundary:

- Which agent is acting?
- Which human or system is accountable?
- Which tool is being called?
- What exact arguments are being passed?
- Is the target production, customer-impacting, sensitive, or irreversible?
- Does policy allow, deny, or require human approval?
- If approved, is the approval bound to the exact action?
- Can the action be audited later?

## Core principles

1. **Agents are not trusted by default**  
   Agents can propose actions; Tanod decides whether those actions can execute.

2. **Tool calls are security events**  
   Every meaningful tool call should be inspectable, governable, and auditable.

3. **Policy lives outside the model**  
   Security decisions should not depend on prompt wording, model behavior, or context-window integrity.

4. **Approval binds to the exact action**  
   A human approval must not be reusable for different arguments, users, tools, systems, or environments.

5. **Audit must be trustworthy**  
   Tanod records a hash-chained event stream so later tampering is detectable.

## High-level architecture

```mermaid
flowchart LR
    User[User / Human] --> Agent[AI Agent / App / Copilot]
    Agent --> Gateway[Tanod Gateway]

    Gateway --> Classifier[Risk Classifier]
    Gateway --> Policy[Policy Engine]
    Gateway --> Approval[Approval Service]
    Gateway --> Audit[Audit Log]

    Policy -->|allow| ToolProxy[Tool Execution Proxy]
    Policy -->|deny| Gateway
    Policy -->|require approval| Approval

    Approval --> Signer[Approval Signer]
    Signer --> Token[Signed Approval Token]
    Token --> ToolProxy

    ToolProxy --> Tools[External Tools / APIs / Systems]
    ToolProxy --> Audit
    Approval --> Audit
    Policy --> Audit

    Audit --> Console[Tanod Console / CLI]
```

## Runtime flow

### Low-risk action

```text
1. Agent requests a read-only diagnostic tool call.
2. Tanod canonicalizes and hashes the arguments.
3. Policy engine returns allow.
4. Tanod records the decision in the audit log.
5. The tool proxy may execute the request.
```

### High-risk action

```text
1. Agent requests a production write action.
2. Tanod classifies the action as high/critical risk.
3. Policy returns require_approval.
4. Human approver reviews the exact action.
5. Tanod signs an approval token containing the tool argument hash.
6. Tool proxy verifies the token and argument hash before execution.
7. Tanod records request, approval, execution, and result events.
```

### Tampering attempt

```text
1. Human approves: grant admin to john@example.com.
2. Agent changes arguments to jane@example.com.
3. Tool proxy recomputes the argument hash.
4. Hash does not match the signed approval token.
5. Tanod blocks execution and records a critical audit event.
```

## Current API

### `GET /healthz`

Returns process status.

### `POST /v1/decisions`

Evaluates a proposed tool call.

Request:

```json
{
  "version": "v1",
  "request_id": "req_demo_001",
  "timestamp": "2026-05-13T13:30:00Z",
  "actor": {
    "user_id": "ross@example.com",
    "roles": ["platform_admin"]
  },
  "agent": {
    "agent_id": "openclaw-main",
    "agent_type": "it-ops-agent",
    "environment": "prod"
  },
  "tool": {
    "name": "shell.exec",
    "category": "infrastructure",
    "operation": "write"
  },
  "target": {
    "system": "homelab-fedora",
    "environment": "prod"
  },
  "arguments": {
    "command": "sudo systemctl restart openclaw-gateway"
  },
  "context": {
    "reason": "Gateway appears unhealthy"
  }
}
```

Response:

```json
{
  "request_id": "req_demo_001",
  "decision": "require_approval",
  "risk_level": "L3",
  "policy_ids": ["approve-prod-shell-write"],
  "argument_hash": "sha256:...",
  "message": "Human approval required before executing shell command on production target."
}
```

### `POST /v1/executions`

Evaluates and attempts to execute a tool call through Tanod's guarded execution pipeline.

Behavior:

- `deny` → execution is blocked before any adapter is invoked
- `allow` → the registered adapter executes immediately
- `require_approval` without token → execution is blocked
- `require_approval` with valid token → token signature, agent, tool, expiry, and argument hash are verified before adapter execution
- Tampered arguments after approval are rejected before execution

Request without approval:

```json
{
  "request": { "...": "tool call request" }
}
```

Request with approval:

```json
{
  "request": { "...": "tool call request" },
  "approval_token": "<compact signed token>"
}
```

Response:

```json
{
  "request_id": "req_demo_001",
  "executed": false,
  "decision": {
    "decision": "require_approval",
    "risk_level": "L3",
    "policy_ids": ["approve-prod-shell-write"],
    "argument_hash": "sha256:..."
  },
  "result": {
    "status": "blocked",
    "adapter": "tanod",
    "error": "Approval token required before execution."
  }
}
```

### `POST /v1/approval-requests`

Creates a persistent pending approval request for a tool call whose policy decision is `require_approval`.

```json
{
  "request": { "...": "tool call request" },
  "requested_by": "ross@example.com"
}
```

Returns `202` with an approval request record containing `approval_id`, status, request, decision, argument hash, and timestamps.

### `GET /v1/approval-requests?status=pending`

Lists approval requests from durable storage. Supported statuses: `pending`, `approved`, `rejected`, `expired`.

### `POST /v1/approval-requests/{approval_id}/approve`

Approves a pending approval request and returns the updated record with a signed approval token bound to the original request arguments.

```json
{
  "approved_by": "ross@example.com",
  "approved_role": "platform_owner",
  "ttl_seconds": 900
}
```

### `POST /v1/approval-requests/{approval_id}/reject`

Rejects a pending approval request.

```json
{
  "rejected_by": "ross@example.com",
  "reason": "Insufficient change context"
}
```

### `POST /v1/approvals`

Signs an approval token immediately for an exact tool-call request. This remains useful for tests and integrations that own their own approval UX; production flows should prefer persistent approval requests.

Request:

```json
{
  "request": { "...": "tool call request from /v1/decisions" },
  "approved_by": "ross@example.com",
  "approved_role": "platform_owner",
  "policy_id": "approve-prod-shell-write",
  "ttl_seconds": 900
}
```

Response:

```json
{
  "approval_token": "<compact signed token>",
  "argument_hash": "sha256:...",
  "expires_at": "2026-05-13T13:45:00.000Z"
}
```

## Policy model

Policies currently use JSON files and a small deterministic matcher. YAML support and pluggable OPA/Cedar evaluation are planned.

Example policy:

```json
{
  "id": "approve-prod-shell-write",
  "description": "Require approval for shell write commands on production systems",
  "when": {
    "tool.name": { "equals": "shell.exec" },
    "tool.operation": { "equals": "write" },
    "target.environment": { "equals": "prod" }
  },
  "then": {
    "decision": "require_approval",
    "risk_level": "L3",
    "message": "Human approval required before executing shell command on production target."
  }
}
```

Supported match operators:

- `equals`
- `contains`
- `contains_any`
- `matches`
- `in`

Policy evaluation is first-match by explicit priority, then file order. If no policy matches, Tanod defaults to `deny`.

## Execution adapters

Tanod now includes a small adapter registry used by `/v1/executions`.

### `shell.exec`

Arguments:

```json
{
  "command": "systemctl status openclaw-gateway"
}
```

Shell execution is **disabled by default**. This is deliberate: Tanod should be safe to run locally and in CI without accidentally becoming a remote command execution service.

Enable it only in a trusted environment:

```bash
TANOD_ENABLE_SHELL_EXECUTION=true npm start
```

When disabled, policy and approval logic still run, but the adapter returns `blocked`.

### `http.request`

Arguments:

```json
{
  "method": "GET",
  "url": "https://example.com",
  "headers": {}
}
```

The HTTP adapter supports `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and `HEAD`. Response bodies are capped in the execution result to avoid unbounded audit payloads.

## Approval console

Tanod serves a minimal built-in approval console at:

```text
http://127.0.0.1:8787/console
```

The console lists pending approval requests, displays exact tool arguments and argument hashes, and can approve or reject requests. If `TANOD_API_KEYS` is configured, enter an API key in the console toolbar.

## Storage

Tanod supports Postgres-backed durable storage. Set `TANOD_DATABASE_URL` to enable it:

```bash
TANOD_DATABASE_URL=postgres://tanod:tanod@localhost:5432/tanod npm start
```

On startup, Tanod creates the required tables if they do not exist. The schema is also documented in `db/schema.sql`.

Durable tables:

- `tanod_tool_calls`
- `tanod_approval_requests`
- `tanod_audit_events`

If `TANOD_DATABASE_URL` is absent, Tanod uses in-memory storage for local development and tests. Postgres should be used for any real deployment.

## API authentication

Set comma-separated API keys to require authentication for all non-health endpoints:

```bash
TANOD_API_KEYS=key-one,key-two npm start
```

Clients can authenticate with either:

```http
Authorization: Bearer key-one
```

or:

```http
x-tanod-api-key: key-one
```

## Repository layout

```text
.
├── src/
│   ├── adapters.ts       # shell/http execution adapters
│   ├── audit.ts          # hash-chained append-only audit events
│   ├── canonical.ts      # stable JSON canonicalization and SHA-256 hashing
│   ├── domain.ts         # core request/decision/token types
│   ├── execution.ts      # guarded decide/approve/execute pipeline
│   ├── index.ts          # process entrypoint
│   ├── policy.ts         # deterministic policy matcher/evaluator
│   ├── server.ts         # HTTP API
│   └── signing.ts        # Ed25519 approval token signing/verification
├── tests/                # node:test coverage
├── examples/
│   ├── policies/         # starter policies
│   └── requests/         # sample agent tool calls
├── db/schema.sql
├── deployments/docker-compose/docker-compose.yml
├── Dockerfile
├── package.json
├── tsconfig.json
└── README.md
```

## Local development

Install dependencies:

```bash
npm install
```

Build and test:

```bash
npm test
```

Run the gateway:

```bash
TANOD_POLICY_FILE=examples/policies/default.json \
TANOD_AUDIT_FILE=.tanod/audit.jsonl \
npm start
```

Defaults:

- Host: `127.0.0.1`
- Port: `8787`
- Policy file: `examples/policies/default.json`
- Audit file: `.tanod/audit.jsonl`
- Postgres URL: optional `TANOD_DATABASE_URL`
- API keys: optional `TANOD_API_KEYS`
- Shell execution: disabled unless `TANOD_ENABLE_SHELL_EXECUTION=true`
- Shell timeout: `10000` ms
- HTTP timeout: `10000` ms

Example decision request:

```bash
curl -sS http://127.0.0.1:8787/v1/decisions \
  -H 'content-type: application/json' \
  --data @examples/requests/shell-write-prod.json | jq
```

Example persistent approval flow:

```bash
# Create a pending approval request.
tanodctl request-approval examples/requests/shell-write-prod.json --by ross@example.com

# List pending approvals.
tanodctl approvals --status pending

# Approve an exact request and receive a signed token.
tanodctl approve appr_... --by ross@example.com --role platform_owner
```

Example guarded execution request:

```bash
jq -n --slurpfile request examples/requests/shell-write-prod.json \
  '{request: $request[0]}' \
  | curl -sS http://127.0.0.1:8787/v1/executions \
      -H 'content-type: application/json' \
      --data @- | jq
```

## v0.1 roadmap

The first release should prove the core idea end-to-end:

- [x] Define tool-call request schema
- [x] Build deterministic policy evaluator
- [x] Implement allow / deny / require-approval decisions
- [x] Compute canonical argument hashes
- [x] Sign approval tokens with Ed25519
- [x] Verify approval tokens against exact arguments
- [x] Write hash-chained audit events
- [x] Add persistent approval queue
- [x] Add execution proxy abstraction
- [x] Add shell adapter
- [x] Add HTTP adapter
- [x] Add `tanodctl` CLI
- [x] Add Docker Compose deployment
- [x] Add basic web approval console
- [x] Add Postgres storage layer
- [x] Add optional API-key auth
- [x] Add GitHub Actions CI

## Positioning

Avoid thinking of Tanod as just another LLM firewall. Tanod is narrower and sharper:

> **No high-risk tool call executes unless policy allows it or a human signs the exact action.**

That signed execution boundary is the product.
