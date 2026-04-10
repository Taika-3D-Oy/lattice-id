#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
trap cleanup EXIT
main() {
  log "Starting Stress Test..."
  start_wash_dev
  log "Registering admin..."
  local password="stress-test-pass"
  register_and_login_superadmin "admin@example.com" "$password" "Admin" > /dev/null
  local CONCURRENCY=4
  local REQUESTS_PER_WORKER=5
  log "Launching $CONCURRENCY workers, each sending $REQUESTS_PER_WORKER login requests..."
  start_time=$(date +%s)
  for i in $(seq 1 $CONCURRENCY); do
    (
      for j in $(seq 1 $REQUESTS_PER_WORKER); do
        curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE_URL/api/login" -H "Content-Type: application/json" -d "{\"email\":\"admin@example.com\",\"password\":\"$password\"}" >> "$TMP_DIR/results.log"
      done
    ) &
  done
  wait
  end_time=$(date +%s)
  duration=$((end_time - start_time))
  total_req=$((CONCURRENCY * REQUESTS_PER_WORKER))
  echo "--- RESULTS ---"
  echo "Requests: $total_req"
  echo "Seconds: $duration"
  [[ $duration -gt 0 ]] && echo "RPS: $(( total_req / duration ))"
  grep -v "200" "$TMP_DIR/results.log" || echo "All 200 OK"
}
main
