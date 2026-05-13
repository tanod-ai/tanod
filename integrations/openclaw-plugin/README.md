# Tanod OpenClaw Plugin

This plugin injects Tanod into OpenClaw's tool execution path.

It supports two modes:

1. **Gate-only mode** (`gate_only`) — intercepts existing OpenClaw tool calls with the `before_tool_call` plugin hook, asks Tanod for a policy decision, blocks denies, and polls Tanod approval requests for approval-required calls. It does not use OpenClaw `/approve` as an authorization source.
2. **Governed replacement mode** (`governed_replacement`) — registers Tanod-backed replacement tools and, by default, blocks configured raw dangerous OpenClaw tools so the model must use governed tools. Approval-required calls wait for a Tanod-signed approval token, then retry Tanod `/v1/executions`.

## Mode 1: gate-only

Gate-only is the easiest way to inject Tanod without changing OpenClaw core or replacing tools.

```json5
{
  "plugins": {
    "entries": {
      "tanod": {
        "enabled": true,
        "config": {
          "mode": "gate_only",
          "tanodUrl": "http://127.0.0.1:8787",
          "apiKeyEnv": "TANOD_API_KEY",
          "actorId": "ross@example.com",
          "agentId": "openclaw-main",
          "defaultEnvironment": "dev"
        }
      }
    }
  }
}
```

Flow:

```text
LLM tool call JSON → OpenClaw parses tool call → Tanod before_tool_call gate → existing OpenClaw tool executor
```

This mode is useful for rollout and observation. Tanod is the approval source of truth: approval-required calls create a Tanod approval request and poll Tanod until approved, rejected, expired, or timed out. OpenClaw `/approve` does not resume these calls. After Tanod approval is verified, OpenClaw still owns final raw-tool execution, so this mode is weaker than governed replacement.

## Mode 2: governed replacement

Governed replacement mode makes Tanod the execution path for supported tools.

```json5
{
  "plugins": {
    "entries": {
      "tanod": {
        "enabled": true,
        "config": {
          "mode": "governed_replacement",
          "tanodUrl": "http://127.0.0.1:8787",
          "apiKeyEnv": "TANOD_API_KEY",
          "actorId": "ross@example.com",
          "agentId": "openclaw-main",
          "defaultEnvironment": "dev",
          "blockRawProtectedToolsInGovernedMode": true
        }
      }
    }
  },
  "tools": {
    "allow": ["tanod", "tanod_exec", "tanod_http_request", "tanod_mcp_call_tool"],
    "deny": ["exec", "bash", "code_execution", "apply_patch", "write", "edit"]
  }
}
```

Registered tools:

- `tanod_exec` → Tanod `shell.exec`
- `tanod_http_request` → Tanod `http.request`
- `tanod_mcp_call_tool` → Tanod `mcp.call_tool`

Flow:

```text
LLM → tanod_* tool → POST /v1/executions → Tanod policy/approval/signature/audit → Tanod adapter executes
```

If Tanod returns `require_approval` and no `approvalToken` is supplied, the plugin creates a Tanod approval request when `createApprovalRequests` is enabled, polls Tanod for completion, then retries `/v1/executions` with the signed approval token. Approve from the Tanod console or CLI; OpenClaw `/approve` is intentionally not used to authorize governed replacement execution.

## Config

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `gate_only` | `gate_only` or `governed_replacement`. |
| `tanodUrl` | `http://127.0.0.1:8787` | Tanod gateway base URL. |
| `apiKey` | unset | Inline Tanod API key. Prefer `apiKeyEnv`. |
| `apiKeyEnv` | `TANOD_API_KEY` | Env var containing the Tanod API key. |
| `actorId` | `openclaw-user` | Actor sent to Tanod. |
| `agentId` | `openclaw` | Agent id sent to Tanod when OpenClaw does not provide one. |
| `agentType` | `openclaw-agent` | Agent type sent to Tanod. |
| `defaultEnvironment` | `dev` | Default agent/target environment. |
| `protectedTools` | `exec`, `bash`, `code_execution`, `apply_patch`, `write`, `edit`, `web_fetch`, `mcp.call_tool` | Raw OpenClaw tools governed by gate-only mode or blocked in governed mode. |
| `blockRawProtectedToolsInGovernedMode` | `true` | Blocks raw protected tools so agents use Tanod replacement tools. |
| `createApprovalRequests` | `true` | Creates Tanod approval requests when a decision requires approval. |
| `approvalRequestedBy` | `openclaw` | `requested_by` for Tanod approval requests. |
| `approvalTimeoutMs` | `600000` | Maximum time to wait for Tanod approval before denying. |
| `approvalPollIntervalMs` | `2000` | Poll interval while waiting for Tanod approval status. |
| `approvalTimeoutBehavior` | `deny` | Legacy config; Tanod approval polling fails closed on timeout. |
| `failClosed` | `true` | Block protected tools when Tanod is unavailable. |

## Security notes

- Gate-only mode is a rollout bridge, not the strongest enforcement model. Tanod approval is required, but OpenClaw still executes the original tool after approval verification.
- Governed replacement mode is stronger because Tanod owns policy, approval verification, execution, and audit. OpenClaw `/approve` cannot substitute for a Tanod-signed approval token.
- For serious use, deny raw dangerous OpenClaw tools and allow only `tanod_*` replacements.
- Keep the Tanod API key in environment/config secrets, not prompt-visible context.
