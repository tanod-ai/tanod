# Tanod local Docker release artifacts

Tanod's local Docker installer is intended for developer/test macOS and Linux machines with Docker already installed. It installs a prebuilt native `tanod` CLI on the host and runs the Tanod gateway plus Postgres under Docker Compose.

The installer does **not** require a Tanod source checkout, Node, or Go. It downloads the matching release artifact from GitHub:

- `tanod_linux_amd64.tar.gz`
- `tanod_linux_arm64.tar.gz`
- `tanod_darwin_amd64.tar.gz`
- `tanod_darwin_arm64.tar.gz`

Each artifact contains:

- `bin/tanod` — prebuilt CLI
- `compose/docker-compose.yml` — runtime Compose file using the published GHCR image
- `VERSION` — release tag
- `IMAGE` — exact container image tag

Install latest release:

```bash
curl -fsSL https://github.com/tanod-ai/tanod/releases/latest/download/install.sh | bash
```

Install a specific release:

```bash
curl -fsSL https://github.com/tanod-ai/tanod/releases/download/v0.1.0-alpha.1/install.sh \
  | bash -s -- --version v0.1.0-alpha.1
```

From a source checkout, this is equivalent:

```bash
scripts/install.sh
```

Defaults:

- Tanod API: `http://127.0.0.1:8787`
- Postgres port: `127.0.0.1:5432`
- State/config: `~/.tanod`
- CLI wrapper: `~/.local/bin/tanod`
- API key: randomly generated and stored in `~/.tanod/.env` plus `~/.tanod/cli.env`
- Shell execution: disabled (`TANOD_ENABLE_SHELL_EXECUTION=false`)
- Private-network HTTP adapter targets: disabled (`TANOD_ALLOW_PRIVATE_NETWORK_HTTP=false`)

Useful options:

```bash
scripts/install.sh --bind 0.0.0.0 --port 8787
scripts/install.sh --api-key dev-key --identity ross@example.com
scripts/install.sh --version v0.1.0-alpha.1
scripts/install.sh --image ghcr.io/tanod-ai/tanod:v0.1.0-alpha.1
scripts/install.sh --no-start
scripts/install.sh --skip-cli
```

The installed `tanod` command is a small wrapper that sources `~/.tanod/cli.env` so the CLI automatically talks to the local Docker-hosted gateway.

Manage services:

```bash
docker compose --project-name tanod --env-file ~/.tanod/.env -f ~/.tanod/compose/docker-compose.yml ps
docker compose --project-name tanod --env-file ~/.tanod/.env -f ~/.tanod/compose/docker-compose.yml logs -f
docker compose --project-name tanod --env-file ~/.tanod/.env -f ~/.tanod/compose/docker-compose.yml down
```

Linux note: the user running the installer must be allowed to access Docker, for example via the `docker` group or rootless Docker.
