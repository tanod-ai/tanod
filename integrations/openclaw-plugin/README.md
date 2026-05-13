# Tanod OpenClaw Plugin

This plugin injects Tanod into OpenClaw's tool execution path.

It supports two modes:

1. **Gate-only mode** (`gate_only`) — intercepts existing OpenClaw tool calls with the `before_tool_call` plugin hook, asks Tanod for a policy decision, blocks denies, and uses OpenClaw's approval pause for approval-required calls.
2. **Governed replacement mode** (`governed_replacement`) — registers Tanod-backed replacement tools and, by default, blocks configured raw dangerous OpenClaw tools so the model must use governed tools.

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

This mode is useful for rollout and observation. Tanod sees and audits decisions before raw OpenClaw tools run, but OpenClaw still owns final execution.

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

If Tanod returns `require_approval` and no `approvalToken` is supplied, the plugin creates a Tanod approval request when `createApprovalRequests` is enabled and returns the approval id in the tool result. Approve it from the Tanod console or CLI, then retry with the signed approval token.

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
| `approvalTimeoutMs` | `600000` | OpenClaw plugin approval timeout in gate-only mode. |
| `approvalTimeoutBehavior` | `deny` | OpenClaw plugin approval timeout behavior. |
| `failClosed` | `true` | Block protected tools when Tanod is unavailable. |

## Security notes

- Gate-only mode is a rollout bridge, not the strongest enforcement model. OpenClaw still executes the original tool after approval.
- Governed replacement mode is stronger because Tanod owns policy, approval verification, execution, and audit.
- For serious use, deny raw dangerous OpenClaw tools and allow only `tanod_*` replacements.
- Keep the Tanod API key in environment/config secrets, not prompt-visible context.
