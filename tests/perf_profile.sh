#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
EMAIL="perf.$(date +%s).${RANDOM}@test.com"

echo "=== OIDC Flow Performance Profile ==="
echo "Base URL: $BASE_URL"
echo "Email: $EMAIL"
echo ""

# Step 1: Register
echo "--- STEP 1: Register ---"
curl -so /dev/null -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  -X POST "$BASE_URL/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"testpass123\",\"name\":\"Perf\"}"

# Step 2: PKCE
CV=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
CC=$(printf '%s' "$CV" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Step 3: Authorize
echo "--- STEP 2: Authorize ---"
curl -so /tmp/perf-auth.html -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=test&nonce=test-nonce&code_challenge=$CC&code_challenge_method=S256"

SID=$(python3 -c "
import re
html = open('/tmp/perf-auth.html').read()
m = re.search(r'name=\"session_id\"\s+value=\"([^\"]+)\"', html)
print(m.group(1) if m else 'NONE')
")
echo "  session_id=$SID"

# Step 4: Login
echo "--- STEP 3: Login (password verify) ---"
curl -so /tmp/perf-login.html -D /tmp/perf-login.headers \
  -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  -X POST "$BASE_URL/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "session_id=$SID&email=$EMAIL&password=testpass123"

LOCATION=$(grep -i '^location:' /tmp/perf-login.headers | tr -d '\r' | sed 's/^[Ll]ocation: *//')
CODE=$(python3 -c "
import urllib.parse
url = '$LOCATION'
q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
print(q.get('code', ['NONE'])[0])
")
echo "  code=$CODE"

# Step 5: Token exchange
echo "--- STEP 4: Token Exchange (JWT sign) ---"
curl -so /tmp/perf-token.json \
  -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  -X POST "$BASE_URL/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$CV&client_id=lid-admin&redirect_uri=http://localhost:8090/callback"

AT=$(python3 -c "import json; print(json.load(open('/tmp/perf-token.json')).get('access_token','NONE')[:50])" 2>/dev/null || echo "NONE")
echo "  token prefix: $AT..."

# Step 6: Userinfo
echo "--- STEP 5: Userinfo ---"
FULL_AT=$(python3 -c "import json; print(json.load(open('/tmp/perf-token.json')).get('access_token',''))" 2>/dev/null)
curl -so /tmp/perf-userinfo.json \
  -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  "$BASE_URL/userinfo" \
  -H "Authorization: Bearer $FULL_AT"

echo ""
echo "=== Repeat login (warm cache) ==="

# Repeat the full flow to see if first-time overhead matters
CV2=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
CC2=$(printf '%s' "$CV2" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "--- Authorize (2nd) ---"
curl -so /tmp/perf-auth2.html -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=test2&nonce=nonce2&code_challenge=$CC2&code_challenge_method=S256"
SID2=$(python3 -c "
import re
html = open('/tmp/perf-auth2.html').read()
m = re.search(r'name=\"session_id\"\s+value=\"([^\"]+)\"', html)
print(m.group(1) if m else 'NONE')
")

echo "--- Login (2nd) ---"
curl -so /tmp/perf-login2.html -D /tmp/perf-login2.headers \
  -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  -X POST "$BASE_URL/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "session_id=$SID2&email=$EMAIL&password=testpass123"

LOCATION2=$(grep -i '^location:' /tmp/perf-login2.headers | tr -d '\r' | sed 's/^[Ll]ocation: *//')
CODE2=$(python3 -c "
import urllib.parse
url = '$LOCATION2'
q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
print(q.get('code', ['NONE'])[0])
")

echo "--- Token Exchange (2nd) ---"
curl -so /tmp/perf-token2.json \
  -w "  HTTP %{http_code} | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n" \
  -X POST "$BASE_URL/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$CODE2&code_verifier=$CV2&client_id=lid-admin&redirect_uri=http://localhost:8090/callback"

echo ""
echo "=== Done ==="
