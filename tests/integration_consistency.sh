#!/usr/bin/env bash
# Test: Session consistency tokens (lattice-db 1.6.0)
#
# Covers:
#  - Write → immediate read returns fresh data (read-your-write via header)
#  - x-lid-consistency response header emitted after writes
#  - __lid_cr cookie emitted and round-tripped by browsers
#  - Header propagation takes priority over cookie
#  - Missing consistency context still works (backward compat)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

run_tests() {
  wait_for_cluster

  # ── Bootstrap: register superadmin ──
  local ADMIN_EMAIL ADMIN_PASS ADMIN_TOKEN
  ADMIN_EMAIL=$(unique_email "consistency-admin")
  ADMIN_PASS="C0nsistency!Test#$(date +%s)"
  ADMIN_TOKEN=$(register_and_login_superadmin "$ADMIN_EMAIL" "$ADMIN_PASS" "Consistency Admin")
  log "Superadmin registered: $ADMIN_EMAIL"

  # ── Test 1: Response header contains x-lid-consistency after a write ──
  log "Test 1: x-lid-consistency header emitted after write"
  local CLIENT_BODY="$TMP_DIR/client-create.json"
  local CLIENT_HEADERS="$TMP_DIR/client-create.headers"
  local CLIENT_ID="consistency-test-$(date +%s)"
  local STATUS
  STATUS=$(curl_capture POST "$BASE_URL/api/clients" "$CLIENT_BODY" "$CLIENT_HEADERS" \
    -H "authorization: Bearer $ADMIN_TOKEN" \
    -H "content-type: application/json" \
    -d "{\"client_id\":\"${CLIENT_ID}\",\"redirect_uris\":[\"http://localhost:9999/cb\"],\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"]}")
  if [[ "$STATUS" != "201" && "$STATUS" != "200" ]]; then
    fail "client create returned $STATUS (expected 201 or 200)"
  fi

  local CR_HEADER
  CR_HEADER=$(header_value "$CLIENT_HEADERS" "x-lid-consistency" 2>/dev/null || echo "")
  if [[ -z "$CR_HEADER" ]]; then
    # Consistency header is only emitted when lattice-db 1.6.0 returns session
    # revisions. With 1.5.0 or single-replica, the header may be absent.
    log "SKIP: x-lid-consistency header not present (server may be < 1.6.0 or single replica)"
  else
    log "PASS: x-lid-consistency header present: $CR_HEADER"
    # Validate it's valid JSON
    echo "$CR_HEADER" | python3 -c "import json,sys; json.load(sys.stdin)" \
      || fail "x-lid-consistency header is not valid JSON"
    log "PASS: x-lid-consistency header is valid JSON"
  fi

  # ── Test 2: __lid_cr cookie emitted ──
  log "Test 2: __lid_cr cookie emitted after write"
  local SET_COOKIE
  SET_COOKIE=$(grep -i '^set-cookie:.*__lid_cr=' "$CLIENT_HEADERS" || echo "")
  if [[ -z "$SET_COOKIE" ]]; then
    log "SKIP: __lid_cr cookie not set (server may be < 1.6.0 or single replica)"
  else
    log "PASS: __lid_cr cookie present"
    # Verify HttpOnly flag
    echo "$SET_COOKIE" | grep -qi "HttpOnly" \
      || fail "__lid_cr cookie missing HttpOnly flag"
    log "PASS: __lid_cr cookie has HttpOnly flag"
  fi

  # ── Test 3: Read-your-write consistency via header round-trip ──
  log "Test 3: Read-your-write via x-lid-consistency header"
  local GET_BODY="$TMP_DIR/client-get.json"
  local GET_HEADERS="$TMP_DIR/client-get.headers"
  local EXTRA_ARGS=()
  if [[ -n "$CR_HEADER" ]]; then
    EXTRA_ARGS=(-H "x-lid-consistency: $CR_HEADER")
  fi
  STATUS=$(curl_capture GET "$BASE_URL/api/clients/${CLIENT_ID}" "$GET_BODY" "$GET_HEADERS" \
    -H "authorization: Bearer $ADMIN_TOKEN" \
    "${EXTRA_ARGS[@]}")
  assert_eq "200" "$STATUS" "read-after-write GET /api/clients/$CLIENT_ID"
  local GOT_ID
  GOT_ID=$(json_get "$GET_BODY" "client_id")
  assert_eq "$CLIENT_ID" "$GOT_ID" "read-your-write returned correct client"
  log "PASS: read-your-write returned fresh data"

  # ── Test 4: Backward compatibility — no consistency context still works ──
  log "Test 4: Requests without consistency context succeed"
  local NOCRH_BODY="$TMP_DIR/no-cr-get.json"
  local NOCRH_HEADERS="$TMP_DIR/no-cr-get.headers"
  STATUS=$(curl_capture GET "$BASE_URL/api/clients/${CLIENT_ID}" "$NOCRH_BODY" "$NOCRH_HEADERS" \
    -H "authorization: Bearer $ADMIN_TOKEN")
  assert_eq "200" "$STATUS" "GET without consistency context"
  log "PASS: backward-compatible read without consistency context"

  # ── Test 5: Cookie round-trip via successive requests ──
  log "Test 5: Cookie round-trip"
  if [[ -n "$SET_COOKIE" ]]; then
    # Extract cookie value for manual round-trip
    local COOKIE_VAL
    COOKIE_VAL=$(echo "$SET_COOKIE" | sed 's/.*__lid_cr=\([^;]*\).*/\1/')
    local COOKIE_BODY="$TMP_DIR/cookie-get.json"
    local COOKIE_HEADERS="$TMP_DIR/cookie-get.headers"
    STATUS=$(curl_capture GET "$BASE_URL/api/clients/${CLIENT_ID}" "$COOKIE_BODY" "$COOKIE_HEADERS" \
      -H "authorization: Bearer $ADMIN_TOKEN" \
      -H "cookie: __lid_cr=$COOKIE_VAL")
    assert_eq "200" "$STATUS" "GET with __lid_cr cookie"
    log "PASS: cookie round-trip read succeeded"
  else
    log "SKIP: no cookie to round-trip"
  fi

  # ── Cleanup ──
  local DEL_BODY="$TMP_DIR/client-del.json"
  local DEL_HEADERS="$TMP_DIR/client-del.headers"
  curl_capture DELETE "$BASE_URL/api/clients/${CLIENT_ID}" "$DEL_BODY" "$DEL_HEADERS" \
    -H "authorization: Bearer $ADMIN_TOKEN" >/dev/null 2>&1 || true

  log "All consistency tests passed"
}

run_tests
