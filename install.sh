#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Installs the aiscoring plugin into Claude Code.
#   ./install.sh                 plugin and Exabeam credentials
#   ./install.sh --with-history  also starts the Neo4j container for rule history
#   ./install.sh --check         checks an existing install, changes nothing
#
# Re-running is safe: it keeps existing credentials and passwords.
set -euo pipefail

SOURCE="${AISCORING_SOURCE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
ENV_FILE="$HOME/.exabeam-mcp.env"
HOME_DIR="${AISCORING_HOME:-$HOME/.aiscoring}"
WITH_HISTORY=0
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --with-history) WITH_HISTORY=1 ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '4,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing '$1'. $2" >&2; exit 1; }
}

need claude "Install Claude Code first: https://claude.com/claude-code"
need uv "Install uv first: https://docs.astral.sh/uv/getting-started/installation/"

umask 077

write_credentials() {
  local url key secret
  read -r -p "Exabeam MCP URL (https://api.<region>.exabeam.cloud/mcp): " url
  read -r -p "API key: " key
  read -r -s -p "API secret (hidden): " secret
  echo
  case "$url" in
    https://*) ;;
    *) echo "the URL must start with https://" >&2; exit 1 ;;
  esac
  [ -n "$key" ] && [ -n "$secret" ] || { echo "key and secret are required" >&2; exit 1; }
  printf 'EXABEAM_MCP_URL=%s\nEXABEAM_API_KEY=%s\nEXABEAM_API_SECRET=%s\n' "$url" "$key" "$secret" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

if [ -f "$ENV_FILE" ]; then
  echo "Keeping the credentials in $ENV_FILE"
  chmod 600 "$ENV_FILE"
elif [ "$CHECK_ONLY" -eq 1 ]; then
  echo "no credentials at $ENV_FILE" >&2; exit 1
else
  write_credentials
fi

echo "Checking the Exabeam connection..."
uv run --quiet "$SOURCE/connector/exabeam-mcp-bridge.py" --check

if [ "$CHECK_ONLY" -eq 1 ]; then
  claude plugin list 2>/dev/null | grep -q aiscoring || { echo "plugin is not installed" >&2; exit 1; }
  echo "Install looks fine."
  exit 0
fi

echo "Installing the plugin from $SOURCE..."
claude plugin marketplace add "$SOURCE" >/dev/null 2>&1 || true  # already added on a re-run
claude plugin install aiscoring@aiscoring

if [ "$WITH_HISTORY" -eq 1 ]; then
  need docker "Install Docker, or run without --with-history. Scoring works without rule history."
  mkdir -p "$HOME_DIR"
  chmod 700 "$HOME_DIR"
  if [ ! -f "$HOME_DIR/neo4j.env" ]; then
    printf 'NEO4J_AUTH=neo4j/%s\n' "$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)" > "$HOME_DIR/neo4j.env"
  fi
  chmod 600 "$HOME_DIR/neo4j.env"
  # shellcheck disable=SC1091
  set -a; . "$HOME_DIR/neo4j.env"; set +a
  (cd "$SOURCE" && docker compose up -d)
  echo "Neo4j is listening on 127.0.0.1:7688. The password is in $HOME_DIR/neo4j.env"
fi

echo "Done. Restart Claude Code, then ask it to \"score case <number>\"."
