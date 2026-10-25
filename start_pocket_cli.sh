#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_BIN="${PYTHON_BIN:-python3}"
PORT="${POCKET_CLI_PORT:-8788}"
SERVER_LOG="/tmp/mith_cli_server.log"

mkdir -p "${APP_DIR}/workspace"

if command -v tmux >/dev/null 2>&1; then
    tmux kill-session -t mith_cli_server 2>/dev/null || true
    sleep 0.4
    tmux new-session -d -s mith_cli_server "${PY_BIN} '${APP_DIR}/pocket_cli_server.py' > '${SERVER_LOG}' 2>&1"
    for _ in $(seq 1 15); do
        if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    echo "✅ MiTH CLI running in background (tmux: mith_cli_server)"
    echo "🔗 Local URL: http://127.0.0.1:${PORT}/cli"
else
    echo "🚀 Starting MiTH CLI on http://127.0.0.1:${PORT}/cli ..."
    exec "${PY_BIN}" "${APP_DIR}/pocket_cli_server.py"
fi
