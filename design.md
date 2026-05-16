# tanod design

This document explains tanod's architecture, API surfaces, authentication model, local development workflow, and server deployment path.

## Purpose

tanod is a signed execution control gateway for AI-agent tool calls. It sits between an agent or automation client and sensitive tools, evaluates policy, records audit evidence, and requires signed human approval for high-risk actions.

The core runtime answers three questions for each tool call:

1. Should this action be allowed, denied, or require approval?
2. If approval is required, who is allowed to approve this exact request?
3. If execution happens, can the result be tied back to the exact approved request and audit chain?

## System Components

The current implementation runs as one Node.js process, but the code is split into browser-facing and machine-facing API boundaries.

| Component | Path | Responsibility |
| --- | --- | --- |
| tanod server runtime | `src/server.ts` | Starts the HTTP server, loads policy/storage/signing keys, authenticates requests, enforces RBAC, evaluates decisions, signs approvals, runs execution adapters, and writes audit events. |
| Browser/server API boundary | `src/server-api.ts` | Exposes console configuration, OAuth2 login/logout/callback routes, and the limited authenticated API surface for browser OAuth/OIDC sessions. |
| Core API boundary | `src/core-api.ts` | Exposes the machine API route boundary used by CLI, OpenClaw, and direct API-key clients. |
| Policy engine | `src/policy.ts` | Evaluates tool-call requests against JSON policy files. |
| Signing | `src/signing.ts` | Creates and verifies signed approval tokens for exact requests. |
| Audit log | `src/audit.ts` | Appends tamper-evident JSONL audit events and coordinates with durable storage. |
| Storage | `src/storage.ts` | Provides in-memory and Postgres-backed records for decisions, approvals, users, invitations, and audit events. |
| Console | `apps/console` | React/Vite UI for login, approvals, audit, policies, agents, users, and invitations. |
| CLI | `cli/cmd/tanod` | Go command-line client for non-interactive core API workflows. |
| OpenClaw plugin | `integrations/openclaw-plugin` | Integrates tanod at OpenClaw's tool-call boundary. |

## Request Routing

`server.ts` owns the actual HTTP server. `core-api.ts` and `server-api.ts` are route gates around the shared handler in `server.ts`.

The request flow is:

```text
request
  -> CORS / OPTIONS handling
  -> unauthenticated server API routes?
       /v1/console-config
       /v1/oauth2/*
  -> authenticate request
  -> if OAuth/OIDC browser session:
       routeServerAuthenticatedApi(...)
     else:
       routeCoreApi(...)
  -> route(...) in server.ts
```

The important split is:

```text
core-api.ts    = "Can this machine/API-key request path enter the core API?"
server-api.ts  = "Can this browser/OAuth request path enter the console API?"
server.ts      = "What does this endpoint actually do, and is this caller allowed?"
```

`core-api.ts` and `server-api.ts` do not implement most business behavior. They decide whether a path is allowed to reach `route(...)` in `server.ts`. Permission checks such as Admin, Approver, Viewer, policy-required roles, and subject matching happen in `server.ts`.

### Core API Boundary

`src/core-api.ts` is the machine/API-key API boundary. It is used by the CLI, OpenClaw plugin, agents, and direct API clients.

Allowed core path patterns:

```text
GET  /healthz
     /v1/me
     /v1/users...
     /v1/invitations...
     /v1/policies...
     /v1/audit-events
     /v1/agents
     /v1/decisions
     /v1/approvals
     /v1/approval-requests...
     /v1/approval-verifications
     /v1/executions
```

The core gate looks like this conceptually:

```ts
export async function routeCoreApi(request, response, handler) {
  if (!isCoreApiRequest(request)) {
    json(response, 404, { error: 'not found' });
    return;
  }
  await handler();
}
```

That means a non-core path returns `404` even if the caller is otherwise authenticated.

### Server/Console API Boundary

`src/server-api.ts` is the browser-facing API boundary.

It exposes unauthenticated server routes:

```text
GET  /v1/console-config
GET  /v1/oauth2/:provider/start
GET  /v1/oauth2/:provider/callback
POST /v1/oauth2/logout
```

It also defines the authenticated browser-session API surface for OAuth/OIDC users:

```text
/v1/me
/v1/users...
/v1/invitations...
/v1/policies...
/v1/audit-events
/v1/agents
/v1/approval-requests...
```

The browser session surface intentionally excludes the machine execution endpoints:

```text
/v1/decisions
/v1/approval-verifications
/v1/executions
```

That keeps OAuth/OIDC browser users on console workflows and keeps machine evaluation/execution on the API-key core surface.

## Endpoint Ownership

The actual endpoint implementations live in `src/server.ts`.

Health and identity:

```text
GET  /healthz
GET  /v1/me
```

Users and invitations:

```text
GET    /v1/users
POST   /v1/users
PATCH  /v1/users/:id
DELETE /v1/users/:id

GET  /v1/invitations
POST /v1/invitations
POST /v1/invitations/:token/accept
```

Policies, audit, and agents:

```text
GET    /v1/policies
PUT    /v1/policies/:id
DELETE /v1/policies/:id

GET /v1/audit-events
GET /v1/agents
```

Policy decisions, approval, and execution:

```text
POST /v1/decisions
POST /v1/approvals

POST /v1/approval-requests
GET  /v1/approval-requests
GET  /v1/approval-requests/:id
POST /v1/approval-requests/:id/approve
POST /v1/approval-requests/:id/reject

POST /v1/approval-verifications
POST /v1/executions
```

OAuth2 and console bootstrap routes are implemented in `src/server-api.ts`:

```text
GET  /v1/console-config
GET  /v1/oauth2/:provider/start
GET  /v1/oauth2/:provider/callback
POST /v1/oauth2/logout
```

## Authentication And Authorization

tanod has three main authentication modes.

### No Configured Auth

If no API keys, OIDC providers, or OAuth2 providers are configured, tanod starts in local development mode. Requests are treated as a development admin on loopback by default.

For non-loopback binds, authentication is required unless `TANOD_ALLOW_UNAUTHENTICATED=true` is explicitly set.

### API Keys

API keys protect the machine-facing core API.

Configure keys with:

```bash
TANOD_API_KEYS=key-one,key-two
```

Clients can send:

```http
Authorization: Bearer key-one
```

or:

```http
x-tanod-api-key: key-one
```

API keys can be mapped to policy approval roles:

```bash
TANOD_API_KEY_ROLES='key-one:platform_owner;key-two:security_owner'
```

API keys can also be bound to identities:

```bash
TANOD_API_KEY_IDENTITIES='key-one:ops@example.com;key-two:sec@example.com'
```

Identity binding matters for approval endpoints because `approved_by` must match the authenticated subject when a subject is known.

API keys are used by:

- `tanod-cli`
- OpenClaw plugin
- direct API integrations
- agents calling `/v1/decisions`, `/v1/approval-requests`, or `/v1/executions`

### OIDC Browser Login

The console can authenticate with OIDC ID tokens. Trusted providers are configured with:

```bash
TANOD_OIDC_PROVIDERS='google|https://accounts.google.com|<google-client-id>'
```

OIDC identities use a stable subject format:

```text
<issuer>#<sub>
```

Email-like claims are display metadata only; they are not used as the account binding key.

After OIDC token verification, tanod requires an active user row for the resolved identity. Users can be managed in the console or with the CLI:

```bash
tanod user add <user-id> <display-name> <role>
```

Policy-required approval roles can be granted to OIDC identities with:

```bash
TANOD_OIDC_IDENTITY_ROLES='<issuer>#<sub>:platform_owner,security_owner'
```

### OAuth2 Browser Login

GitHub and other OAuth2 providers can be configured as server-side OAuth2 providers. The browser never receives the client secret.

For GitHub:

```bash
tanod config oauth add github \
  --client-id <github-client-id> \
  --client-secret <github-client-secret>
```

The OAuth2 provider configuration is loaded from the tanod runtime config file:

```text
$TANOD_CONFIG_FILE
```

or, if unset:

```text
~/.config/tanod/config.json
```

The server reads this path from its own runtime environment. In Docker, make sure the config file is mounted into the container and `TANOD_CONFIG_FILE` points at the mounted path.

The externally reachable callback origin is controlled by:

```bash
TANOD_OAUTH_CALLBACK_BASE_URL=http://<server-host>:8787
```

The GitHub OAuth app callback URL should be:

```text
http://<server-host>:8787/v1/oauth2/github/callback
```

Successful OAuth2 login sets an HttpOnly `tanod_session` cookie. The console then uses credentialed fetches to call the authenticated console API.

When the console is hosted separately from the API, configure:

```bash
TANOD_CONSOLE_BASE_URL=http://<console-host>:5173
```

This controls allowed OAuth redirect origins and credentialed CORS responses.

## Authorization Roles

tanod has console/RBAC roles:

```text
Admin
Approver
Viewer
```

It also supports policy-required approval roles such as:

```text
platform_owner
security_owner
system_owner
```

RBAC roles control console and management permissions:

- `Admin` can manage users, invitations, and policies.
- `Approver` can approve or reject approval requests, subject to policy-required role checks.
- `Viewer` can read console data.

Policy-required roles control whether a signed approval token can be issued for a specific policy. Approval-required policies fail closed unless the authenticated identity has one of the required roles.

## Console API Usage

The console is the React/Vite app in `apps/console`.

On startup it calls:

```text
GET /v1/console-config
```

That response tells the console:

- the API base URL
- configured OIDC providers
- configured OAuth2 providers such as GitHub

If OAuth2 providers are present, the login page renders provider buttons. If no provider is configured or the config fetch fails, it falls back to local development login behavior.

After login, the console primarily calls:

```text
GET  /v1/me
GET  /v1/approval-requests
GET  /v1/approval-requests/:id
POST /v1/approval-requests/:id/approve
POST /v1/approval-requests/:id/reject
GET  /v1/audit-events
GET  /v1/policies
PUT  /v1/policies/:id
DELETE /v1/policies/:id
GET  /v1/agents
GET  /v1/users
POST /v1/users
PATCH /v1/users/:id
DELETE /v1/users/:id
GET  /v1/invitations
POST /v1/invitations
POST /v1/invitations/:token/accept
POST /v1/oauth2/logout
```

Browser OAuth/OIDC sessions are routed through `routeServerAuthenticatedApi`, so they do not get the core execution endpoints.

## CLI API Usage

The CLI is a non-interactive machine client. It talks to the core API and cannot use browser OAuth/OIDC.

CLI commands map to these endpoints:

| CLI command | Endpoint |
| --- | --- |
| `tanod decide <request.json>` | `POST /v1/decisions` |
| `tanod execute <request.json> --token <token>` | `POST /v1/executions` |
| `tanod request-approval <request.json>` | `POST /v1/approval-requests` |
| `tanod approvals --status pending` | `GET /v1/approval-requests?status=pending` |
| `tanod approve <approval-id>` | `POST /v1/approval-requests/:id/approve` |
| `tanod reject <approval-id>` | `POST /v1/approval-requests/:id/reject` |
| `tanod user ls` | `GET /v1/users` |
| `tanod user add ...` | `POST /v1/users` |
| `tanod user delete ...` | `DELETE /v1/users/:id` |

The CLI reads:

```text
TANOD_URL
TANOD_API_KEY
TANOD_CONFIG_FILE
```

It stores config in:

```text
~/.config/tanod/config.json
```

unless `TANOD_CONFIG_FILE` is set.

## Storage And Audit Design

Without `TANOD_DATABASE_URL`, tanod uses in-memory storage. That is useful for local development and tests but should not be used for real deployments.

With Postgres enabled:

```bash
TANOD_DATABASE_URL=postgres://tanod:tanod@localhost:5432/tanod
```

tanod persists:

- tool call decisions
- approval requests
- users
- invitations
- audit events

The audit log is also written to JSONL. On startup, tanod checks the JSONL audit chain head against durable storage before appending. If the heads disagree, it refuses to append rather than silently fork the chain.

Approval tokens are signed with the server's Ed25519 key material. The key files are configured by:

```text
TANOD_PRIVATE_KEY_FILE
TANOD_PUBLIC_KEY_FILE
```

## Execution Adapters

tanod supports execution adapters for governed execution.

Current adapters include:

- `shell.exec`
- `http.request`
- `mcp.call_tool`

Shell execution is disabled by default:

```bash
TANOD_ENABLE_SHELL_EXECUTION=true
```

Private-network HTTP targets are blocked by default:

```bash
TANOD_ALLOW_PRIVATE_NETWORK_HTTP=true
```

HTTP redirects are blocked.

## Local Development

Install dependencies:

```bash
npm install
```

Build and run tests:

```bash
npm test
npm test --prefix integrations/openclaw-plugin
```

Run the gateway in development mode:

```bash
npm run dev
```

By default, the gateway binds to:

```text
http://127.0.0.1:8787
```

For LAN or Tailscale access, bind explicitly and configure API keys:

```bash
TANOD_HOST=0.0.0.0 \
TANOD_API_KEYS=dev-key \
TANOD_API_KEY_ROLES=dev-key:platform_owner \
TANOD_API_KEY_IDENTITIES=dev-key:ross@example.com \
npm run dev
```

Run the console in another terminal:

```bash
cd apps/console
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

The Vite dev server proxies `/v1` and `/healthz` to `http://127.0.0.1:8787`. For a remote gateway, set the API base in the console UI or run with:

```bash
VITE_TANOD_API_BASE=http://<gateway-host>:8787 npm run dev
```

Build the console:

```bash
cd apps/console
npm run build
```

Build the native CLI:

```bash
mkdir -p bin
(cd cli && go build -o ../bin/tanod ./cmd/tanod)
```

Run CLI checks:

```bash
export TANOD_URL=http://127.0.0.1:8787
export TANOD_API_KEY=dev-key

./bin/tanod help
./bin/tanod decide examples/requests/shell-write-prod.json
./bin/tanod request-approval examples/requests/shell-write-prod.json --by ross@example.com
./bin/tanod approvals --status pending
```

## Local Docker Install

tanod publishes release artifacts that include:

- prebuilt CLI
- Docker Compose bundle
- installer script
- checksums

Install the latest release:

```bash
curl -fsSL https://github.com/tanod-ai/tanod/releases/latest/download/install.sh | bash
```

Install from a source checkout:

```bash
scripts/install.sh
```

Common installer options:

```bash
scripts/install.sh --bind 0.0.0.0 --port 8787
scripts/install.sh --api-key dev-key --identity ross@example.com
scripts/install.sh --version v0.1.0-alpha.1
scripts/install.sh --no-start
```

Default install locations:

```text
State/config: ~/.tanod
CLI wrapper: ~/.local/bin/tanod
Compose file: ~/.tanod/compose/docker-compose.yml
Environment file: ~/.tanod/.env
CLI env file: ~/.tanod/cli.env
```

The installer runs:

- `tanod-core`
- Postgres

The server data volume stores signing keys and audit JSONL under `/data`. Postgres stores durable records in its own Docker volume.

## Server Deployment

For a server deployment, use Docker Compose with Postgres.

Important deployment settings:

```bash
TANOD_BIND_ADDR=0.0.0.0
TANOD_HOST_PORT=8787
TANOD_API_KEYS=<strong-api-key>
TANOD_API_KEY_ROLES='<key>:platform_owner,security_owner'
TANOD_API_KEY_IDENTITIES='<key>:ops@example.com'
```

For OAuth2 login on a server or Tailscale host:

```bash
tanod config oauth add github \
  --client-id <github-client-id> \
  --client-secret <github-client-secret>
```

Make sure the running server can read the same config file. For Docker, mount the config and set:

```yaml
environment:
  TANOD_CONFIG_FILE: /config/config.json
  TANOD_CONSOLE_BASE_URL: http://<tailscale-host>:8787
  TANOD_OAUTH_CALLBACK_BASE_URL: http://<tailscale-host>:8787
volumes:
  - tanod-core-data:/data
  - /home/<user>/.config/tanod/config.json:/config/config.json:ro
```

Register this GitHub OAuth callback URL:

```text
http://<tailscale-host>:8787/v1/oauth2/github/callback
```

If the console and API are on different origins, configure:

```bash
TANOD_CONSOLE_BASE_URL=http://<console-host>:5173
TANOD_CONSOLE_API_BASE_URL=http://<api-host>:8787
TANOD_OAUTH_CALLBACK_BASE_URL=http://<api-host>:8787
```

For cross-site console/API deployments, use HTTPS so the OAuth session cookie can use `SameSite=None; Secure`.

After changing OAuth, OIDC, or runtime config, restart `tanod-core`; runtime config is loaded at startup.

## Release Packaging

The release workflow builds:

- Docker image
- Linux and macOS CLI tarballs for amd64 and arm64
- install script
- checksum file

Release packages include a Compose bundle that runs the published server image and Postgres.

## Operational Notes

- Use API keys whenever tanod is reachable beyond loopback.
- Use Postgres for any real deployment.
- Keep shell execution disabled unless the host is trusted and policy is strict.
- Keep private-network HTTP blocked unless the gateway is intentionally allowed to reach internal services.
- Mount runtime config into Docker when using OAuth2 providers configured by the CLI.
- Restart the server after changing runtime config.
- Use `/v1/console-config` to verify what the browser will see for API base URL and login providers.
