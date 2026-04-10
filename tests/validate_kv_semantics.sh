#!/usr/bin/env bash
# S4.4: Validate JetStream KV semantics on a real NATS cluster (Kind)
#
# Tests the KV operations Lattice-ID depends on:
#   1. Bucket creation (add)
#   2. kv put / kv get (basic CRUD)
#   3. kv create (create-if-absent / optimistic concurrency)
#   4. kv update with revision (CAS)
#   5. kv list keys
#   6. kv delete
#   7. Key character validation (sanitize_key compatibility)
#   8. Bucket isolation (different prefixes don't collide)
#
# Prerequisites:
#   - Kind cluster "wasmcloud" running with NATS pod
#   - kubectl, nats CLI installed locally
#
# Usage:
#   bash tests/validate_kv_semantics.sh
set -euo pipefail

PASS=0
FAIL=0
BUCKET_PREFIX="kv-test-$$"
TLS_DIR="$(mktemp -d)"
PF_PID=""

log()  { echo "INFO:  $*" >&2; }
pass() { PASS=$((PASS + 1)); echo "PASS:  $1" >&2; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL:  $1" >&2; }

cleanup() {
  log "Cleaning up..."
  # Remove test buckets
  for b in "${BUCKET_PREFIX}-a" "${BUCKET_PREFIX}-b"; do
    nats_cmd kv rm "$b" -f 2>/dev/null || true
  done
  # Delete nats-box pod
  kubectl delete pod "$NATS_BOX_POD" --force --grace-period=0 2>/dev/null || true
  rm -rf "$TLS_DIR"
}
trap cleanup EXIT

# ── Setup: launch nats-box pod with TLS certs ────────────────────

NATS_BOX_POD="kv-test-$$"

log "Launching nats-box pod..."
kubectl run "$NATS_BOX_POD" \
  --image=natsio/nats-box:latest \
  --restart=Never \
  --overrides='{
    "spec": {
      "volumes": [{"name":"tls","secret":{"secretName":"wasmcloud-data-tls"}}],
      "containers": [{
        "name":"nats-box",
        "image":"natsio/nats-box:latest",
        "stdin":true,"tty":false,
        "command":["sleep","3600"],
        "volumeMounts":[{"name":"tls","mountPath":"/tls","readOnly":true}]
      }]
    }
  }' >/dev/null 2>&1

log "Waiting for nats-box to be ready..."
kubectl wait --for=condition=Ready "pod/$NATS_BOX_POD" --timeout=30s >/dev/null 2>&1

nats_cmd() {
  kubectl exec "$NATS_BOX_POD" -- \
    nats --server nats://nats:4222 \
      --tlscert /tls/tls.crt --tlskey /tls/tls.key --tlsca /tls/ca.crt \
      "$@" 2>&1
}

# ── 1. Bucket creation ──────────────────────────────────────────

log "=== Test 1: Bucket creation ==="
out=$(nats_cmd kv add "${BUCKET_PREFIX}-a" 2>&1)
if echo "$out" | grep -qi "created\|bucket\|Information"; then
  pass "bucket ${BUCKET_PREFIX}-a created"
else
  fail "bucket creation failed: $out"
fi

out=$(nats_cmd kv add "${BUCKET_PREFIX}-b" 2>&1)
if echo "$out" | grep -qi "created\|bucket\|Information"; then
  pass "bucket ${BUCKET_PREFIX}-b created"
else
  fail "bucket creation failed: $out"
fi

# ── 2. Basic put / get ──────────────────────────────────────────

log "=== Test 2: Basic put/get ==="
nats_cmd kv put "${BUCKET_PREFIX}-a" "user/alice" '{"id":"u1","email":"alice@test.local"}' >/dev/null
val=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "user/alice" --raw)
if echo "$val" | grep -q '"alice@test.local"'; then
  pass "put/get round-trip works"
else
  fail "get returned unexpected value: $val"
fi

# ── 3. Create-if-absent (kv create) ─────────────────────────────

log "=== Test 3: Create-if-absent semantics ==="
# First create should succeed — nats kv create echoes the value on success
out=$(nats_cmd kv create "${BUCKET_PREFIX}-a" "bootstrap/done" "true")
if [[ "$out" == "true" ]]; then
  pass "kv create succeeds on new key"
else
  fail "kv create failed: $out"
fi

# Second create should fail with "key exists"
out=$(nats_cmd kv create "${BUCKET_PREFIX}-a" "bootstrap/done" "true2" || true)
if echo "$out" | grep -qi "key exists\|wrong last sequence"; then
  pass "kv create correctly rejects duplicate"
else
  fail "kv create should have rejected duplicate: $out"
fi

# Verify original value is preserved
val=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "bootstrap/done" --raw)
if [[ "$val" == "true" ]]; then
  pass "original value preserved after failed create"
else
  fail "value changed after failed create: $val"
fi

# ── 4. Update with revision (CAS) ───────────────────────────────

log "=== Test 4: CAS update with revision ==="
# Put a value and capture revision from the "revision: N" line
nats_cmd kv put "${BUCKET_PREFIX}-a" "counter" "0" >/dev/null
rev_output=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "counter" 2>&1)
# Format: "bucket > counter revision: 4 created @ ..."
revision=$(echo "$rev_output" | grep -oE 'revision: [0-9]+' | grep -oE '[0-9]+')

if [[ -n "$revision" ]]; then
  # Update with correct revision should succeed (echoes value)
  out=$(nats_cmd kv update "${BUCKET_PREFIX}-a" "counter" "1" "$revision")
  if [[ "$out" == "1" ]]; then
    pass "CAS update with correct revision succeeds"
  else
    fail "CAS update failed: $out"
  fi

  # Update with stale revision should fail
  out=$(nats_cmd kv update "${BUCKET_PREFIX}-a" "counter" "2" "$revision" || true)
  if echo "$out" | grep -qi "wrong last sequence"; then
    pass "CAS update with stale revision correctly rejected"
  else
    fail "CAS update should have rejected stale revision: $out"
  fi

  # Verify value stayed at "1" (not "2")
  val=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "counter" --raw)
  if [[ "$val" == "1" ]]; then
    pass "value unchanged after rejected CAS update"
  else
    fail "value changed after rejected CAS: $val"
  fi
else
  fail "could not extract revision from: $rev_output"
fi

# ── 5. Key listing ──────────────────────────────────────────────

log "=== Test 5: Key listing ==="
# Add a few more keys
nats_cmd kv put "${BUCKET_PREFIX}-a" "session/abc123" '{"code":"xyz"}' >/dev/null
nats_cmd kv put "${BUCKET_PREFIX}-a" "session/def456" '{"code":"uvw"}' >/dev/null

keys=$(nats_cmd kv ls "${BUCKET_PREFIX}-a" 2>&1)
if echo "$keys" | grep -q "user/alice" && echo "$keys" | grep -q "session/abc123"; then
  pass "kv ls returns expected keys"
else
  fail "kv ls output unexpected: $keys"
fi

# ── 6. Key deletion ─────────────────────────────────────────────

log "=== Test 6: Key deletion ==="
nats_cmd kv del "${BUCKET_PREFIX}-a" "session/abc123" -f >/dev/null 2>&1
val=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "session/abc123" --raw || true)
if echo "$val" | grep -qi "not found\|error" || [[ -z "$val" ]]; then
  pass "deleted key returns not-found"
else
  fail "deleted key still has value: $val"
fi

# ── 7. Key character validation (sanitize_key compatibility) ─────

log "=== Test 7: Key character validation ==="

# Valid keys (the sanitized format Lattice-ID uses)
for key in "email/alice_at_test.local" "refresh/abc-def_123" "audit/1712345678/a1b2"; do
  out=$(nats_cmd kv put "${BUCKET_PREFIX}-a" "$key" "ok" 2>&1)
  if ! echo "$out" | grep -qi "error\|invalid"; then
    pass "valid key accepted: $key"
  else
    fail "valid key rejected: $key → $out"
  fi
done

# Invalid keys (raw format before sanitization — these should fail)
for key in "email:alice@test.local" "session:abc+def"; do
  out=$(nats_cmd kv put "${BUCKET_PREFIX}-a" "$key" "fail" || true)
  if echo "$out" | grep -qi "error\|invalid"; then
    pass "invalid key correctly rejected: $key"
  else
    # NATS might silently accept some; check what actually happened
    fail "invalid key was accepted (NATS may be lenient): $key"
  fi
done

# ── 8. Bucket isolation ─────────────────────────────────────────

log "=== Test 8: Bucket isolation ==="
nats_cmd kv put "${BUCKET_PREFIX}-b" "user/alice" '{"id":"u99","email":"alice@other.local"}' >/dev/null

val_a=$(nats_cmd kv get "${BUCKET_PREFIX}-a" "user/alice" --raw)
val_b=$(nats_cmd kv get "${BUCKET_PREFIX}-b" "user/alice" --raw)

if echo "$val_a" | grep -q "alice@test.local" && echo "$val_b" | grep -q "alice@other.local"; then
  pass "bucket isolation: same key in different buckets holds different values"
else
  fail "bucket isolation broken: a=$val_a b=$val_b"
fi

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo "========================================"
echo " JetStream KV Semantics Validation"
echo "========================================"
echo " PASSED: $PASS"
echo " FAILED: $FAIL"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
