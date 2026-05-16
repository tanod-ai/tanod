#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Install tanod on macOS or Linux from GitHub release artifacts.

Usage:
  scripts/install.sh [options]

Options:
  --repo <owner/name>       GitHub repository (default: tanod-ai/tanod)
  --version <tag|latest>    Release tag or latest (default: latest)
  --artifact-url <url>      Explicit artifact tarball URL; bypasses repo/version URL construction
  --home <dir>              tanod state/config dir (default: ~/.tanod)
  --prefix <dir>            CLI wrapper install prefix (default: ~/.local)
  --bind <addr>             Host bind address for tanod API (default: 127.0.0.1)
  --port <port>             Host port for tanod API (default: 8787)
  --postgres-port <port>    Host port for Postgres (default: 5432)
  --image <image>           Container image override (default: artifact metadata)
  --api-key <key>           API key to configure (default: generated random key)
  --identity <identity>     API key identity (default: operator@example.com)
  --roles <roles>           Comma-separated roles (default: platform_owner,system_owner,security_owner)
  --skip-cli                Do not install the local CLI binary
  --no-start                Write files/install CLI but do not start Docker services
  -h, --help                Show this help

Environment overrides are also supported: TANOD_GITHUB_REPO, TANOD_VERSION,
TANOD_ARTIFACT_URL, TANOD_HOME, PREFIX, TANOD_BIN_DIR, TANOD_BIND_ADDR,
TANOD_HOST_PORT, TANOD_POSTGRES_HOST_PORT, TANOD_IMAGE, TANOD_API_KEY,
TANOD_API_IDENTITY, TANOD_API_ROLES, TANOD_ENABLE_SHELL_EXECUTION,
TANOD_ALLOW_PRIVATE_NETWORK_HTTP.
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\''/g")"
}

generate_api_key() {
  if have openssl; then
    openssl rand -base64 32 | tr -d '\n'
  elif have python3; then
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32), end='')
PY
  else
    echo "error: openssl or python3 is required to generate an API key; pass --api-key instead" >&2
    exit 1
  fi
}

normalize_os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *) echo "error: unsupported OS: $(uname -s) (supported: macOS/Darwin and Linux)" >&2; exit 1 ;;
  esac
}

normalize_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "error: unsupported architecture: $(uname -m) (supported: amd64, arm64)" >&2; exit 1 ;;
  esac
}

wait_for_health() {
  local url="$1"
  local key="$2"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if curl -fsS -H "authorization: Bearer ${key}" "$url/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
  esac
done

OS="$(normalize_os)"
ARCH="$(normalize_arch)"
REPO="${TANOD_GITHUB_REPO:-tanod-ai/tanod}"
VERSION="${TANOD_VERSION:-latest}"
ARTIFACT_URL="${TANOD_ARTIFACT_URL:-}"
TANOD_HOME="${TANOD_HOME:-$HOME/.tanod}"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="${TANOD_BIN_DIR:-$PREFIX/bin}"
BIND_ADDR="${TANOD_BIND_ADDR:-127.0.0.1}"
HOST_PORT="${TANOD_HOST_PORT:-${TANOD_PORT:-8787}}"
POSTGRES_HOST_PORT="${TANOD_POSTGRES_HOST_PORT:-${TANOD_POSTGRES_PORT:-5432}}"
IMAGE_OVERRIDE="${TANOD_IMAGE:-}"
API_KEY="${TANOD_API_KEY:-}"
API_IDENTITY="${TANOD_API_IDENTITY:-operator@example.com}"
API_ROLES="${TANOD_API_ROLES:-platform_owner,system_owner,security_owner}"
SKIP_CLI=0
START_SERVICES=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --artifact-url) ARTIFACT_URL="$2"; shift 2 ;;
    --home) TANOD_HOME="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; BIN_DIR="$PREFIX/bin"; shift 2 ;;
    --bind) BIND_ADDR="$2"; shift 2 ;;
    --port) HOST_PORT="$2"; shift 2 ;;
    --postgres-port) POSTGRES_HOST_PORT="$2"; shift 2 ;;
    --image) IMAGE_OVERRIDE="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --identity) API_IDENTITY="$2"; shift 2 ;;
    --roles) API_ROLES="$2"; shift 2 ;;
    --skip-cli) SKIP_CLI=1; shift ;;
    --no-start) START_SERVICES=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$API_KEY" ]]; then
  API_KEY="$(generate_api_key)"
fi

if ! have curl; then
  echo "error: curl is required to download tanod release artifacts" >&2
  exit 1
fi
if ! have tar; then
  echo "error: tar is required to extract tanod release artifacts" >&2
  exit 1
fi
if [[ "$START_SERVICES" -eq 1 ]]; then
  if ! have docker; then
    echo "error: docker CLI not found. Install Docker Desktop (macOS) or Docker Engine/Desktop (Linux) first." >&2
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "error: docker compose plugin not available. Install/update Docker Desktop or the Docker Compose plugin." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "error: Docker is installed but not reachable. Start Docker Desktop or the Docker daemon and retry." >&2
    exit 1
  fi
fi

ASSET="tanod_${OS}_${ARCH}.tar.gz"
if [[ -z "$ARTIFACT_URL" ]]; then
  if [[ "$VERSION" == "latest" ]]; then
    ARTIFACT_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  else
    ARTIFACT_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
  fi
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tanod-install.XXXXXX")"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

ARCHIVE="$TMP_DIR/$ASSET"
echo "Downloading tanod artifact: $ARTIFACT_URL"
curl -fL --retry 3 --retry-delay 2 -o "$ARCHIVE" "$ARTIFACT_URL"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"

PKG_DIR="$TMP_DIR/package"
if [[ ! -d "$PKG_DIR" ]]; then
  # Accept archives that unpack directly at the root for manual testing.
  PKG_DIR="$TMP_DIR"
fi

if [[ ! -f "$PKG_DIR/compose/docker-compose.yml" ]]; then
  echo "error: artifact missing compose/docker-compose.yml" >&2
  exit 1
fi
if [[ "$SKIP_CLI" -eq 0 && ! -x "$PKG_DIR/bin/tanod" ]]; then
  echo "error: artifact missing executable bin/tanod" >&2
  exit 1
fi

ARTIFACT_VERSION="unknown"
if [[ -f "$PKG_DIR/VERSION" ]]; then
  ARTIFACT_VERSION="$(tr -d '\r\n' < "$PKG_DIR/VERSION")"
fi
ARTIFACT_IMAGE=""
if [[ -f "$PKG_DIR/IMAGE" ]]; then
  ARTIFACT_IMAGE="$(tr -d '\r\n' < "$PKG_DIR/IMAGE")"
fi
TANOD_IMAGE_EFFECTIVE="${IMAGE_OVERRIDE:-$ARTIFACT_IMAGE}"
if [[ -z "$TANOD_IMAGE_EFFECTIVE" ]]; then
  echo "error: artifact missing IMAGE metadata; pass --image" >&2
  exit 1
fi

mkdir -p "$TANOD_HOME" "$TANOD_HOME/compose" "$TANOD_HOME/bin" "$BIN_DIR"
chmod 700 "$TANOD_HOME"

COMPOSE_FILE="$TANOD_HOME/compose/docker-compose.yml"
ENV_FILE="$TANOD_HOME/.env"
CLI_ENV_FILE="$TANOD_HOME/cli.env"
cp "$PKG_DIR/compose/docker-compose.yml" "$COMPOSE_FILE"

if [[ "$SKIP_CLI" -eq 0 ]]; then
  cp "$PKG_DIR/bin/tanod" "$TANOD_HOME/bin/tanod-bin"
  chmod 755 "$TANOD_HOME/bin/tanod-bin"
  cat > "$BIN_DIR/tanod" <<WRAPPER
#!/bin/sh
if [ -f $(shell_quote "$CLI_ENV_FILE") ]; then
  . $(shell_quote "$CLI_ENV_FILE")
fi
exec $(shell_quote "$TANOD_HOME/bin/tanod-bin") "\$@"
WRAPPER
  chmod 755 "$BIN_DIR/tanod"
fi

cat > "$ENV_FILE" <<ENV
TANOD_IMAGE=$TANOD_IMAGE_EFFECTIVE
TANOD_VERSION=$ARTIFACT_VERSION
TANOD_BIND_ADDR=$BIND_ADDR
TANOD_HOST_PORT=$HOST_PORT
TANOD_POSTGRES_BIND_ADDR=127.0.0.1
TANOD_POSTGRES_HOST_PORT=$POSTGRES_HOST_PORT
TANOD_POSTGRES_USER=tanod
TANOD_POSTGRES_PASSWORD=tanod
TANOD_POSTGRES_DB=tanod
TANOD_API_KEYS=$API_KEY
TANOD_API_KEY_ROLES=$API_KEY:$API_ROLES
TANOD_API_KEY_IDENTITIES=$API_KEY:$API_IDENTITY
TANOD_ENABLE_SHELL_EXECUTION=${TANOD_ENABLE_SHELL_EXECUTION:-false}
TANOD_ALLOW_PRIVATE_NETWORK_HTTP=${TANOD_ALLOW_PRIVATE_NETWORK_HTTP:-false}
ENV
chmod 600 "$ENV_FILE"

{
  echo "export TANOD_URL=$(shell_quote "http://${BIND_ADDR}:${HOST_PORT}")"
  echo "export TANOD_API_KEY=$(shell_quote "$API_KEY")"
} > "$CLI_ENV_FILE"
chmod 600 "$CLI_ENV_FILE"

if [[ "$START_SERVICES" -eq 1 ]]; then
  echo "Starting tanod Docker services with image: $TANOD_IMAGE_EFFECTIVE"
  docker compose --project-name tanod --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d
  if wait_for_health "http://${BIND_ADDR}:${HOST_PORT}" "$API_KEY"; then
    echo "tanod is healthy at http://${BIND_ADDR}:${HOST_PORT}"
  else
    echo "warning: tanod did not become healthy within 60s; inspect with:" >&2
    echo "  docker compose --project-name tanod --env-file $(shell_quote "$ENV_FILE") -f $(shell_quote "$COMPOSE_FILE") logs" >&2
  fi
fi

cat <<SUMMARY

tanod install complete.

Version:
  $ARTIFACT_VERSION

Image:
  $TANOD_IMAGE_EFFECTIVE

CLI:
  $BIN_DIR/tanod

Config/state:
  $TANOD_HOME
  $ENV_FILE
  $CLI_ENV_FILE

Docker services:
  docker compose --project-name tanod --env-file $(shell_quote "$ENV_FILE") -f $(shell_quote "$COMPOSE_FILE") ps
  docker compose --project-name tanod --env-file $(shell_quote "$ENV_FILE") -f $(shell_quote "$COMPOSE_FILE") logs -f
  docker compose --project-name tanod --env-file $(shell_quote "$ENV_FILE") -f $(shell_quote "$COMPOSE_FILE") down

If $BIN_DIR is not on PATH, add this to your shell profile:
  export PATH=$(shell_quote "$BIN_DIR"):\$PATH

Try:
  tanod help
  tanod approvals --status pending
SUMMARY
