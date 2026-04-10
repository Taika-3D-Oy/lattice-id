#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$ROOT/.dev-pids"
WASH="${WASH:-$HOME/.cargo/bin/wash}"

case "${1:-start}" in
  start)
    if [[ -f "$PIDFILE" ]]; then
      echo "Dev system may already be running (found $PIDFILE). Run: $0 stop"
      exit 1
    fi

    mkdir -p "$ROOT/dev-data/keyvalue"

    echo "Starting wash dev (backend :8000)..."
    cd "$ROOT"
    nohup "$WASH" dev --non-interactive > "$ROOT/.wash-dev.log" 2>&1 &
    WASH_PID=$!

    echo "Starting trunk serve (admin UI :8091)..."
    cd "$ROOT/admin-ui"
    nohup trunk serve > "$ROOT/.trunk-serve.log" 2>&1 &
    TRUNK_PID=$!

    echo "$WASH_PID" > "$PIDFILE"
    echo "$TRUNK_PID" >> "$PIDFILE"

    echo "Waiting for components to load (~10-30s)..."
    for i in $(seq 1 60); do
      STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/api/bootstrap/status 2>/dev/null || echo "000")
      if [ "$STATUS" = "200" ]; then
        echo "Backend ready."
        break
      fi
      sleep 1
    done

    echo ""
    echo "  Backend:  http://localhost:8000"
    echo "  Admin UI: http://localhost:8091"
    echo ""
    echo "Logs: wash dev and trunk serve are running in background."
    echo "Stop: $0 stop"
    ;;

  stop)
    if [[ -f "$PIDFILE" ]]; then
      while read -r pid; do
        kill "$pid" 2>/dev/null || true
      done < "$PIDFILE"
      rm -f "$PIDFILE"
      echo "Stopped."
    else
      echo "No pidfile found — killing by name..."
      pkill -f "wash dev" 2>/dev/null || true
      pkill -f "trunk serve" 2>/dev/null || true
      echo "Done."
    fi
    ;;

  reset)
    "$0" stop
    echo "Clearing KV data..."
    rm -rf "$ROOT/dev-data"
    echo "Run '$0 start' for a fresh bootstrap."
    ;;

  *)
    echo "Usage: $0 {start|stop|reset}"
    exit 1
    ;;
esac
