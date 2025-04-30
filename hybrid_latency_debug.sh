#!/usr/bin/env bash
set -euo pipefail

# ─── Arguments ──────────────────────────────────────────────────────────────
TLS_SIGN=${1:-kyber512}
JWT_SIGN=${2:-falcon512}

# ─── Configuration ───────────────────────────────────────────────────────────
OP_CONTAINER="op-pqc-tls"
RP_CONTAINER="rp-test"
CLIENT_ID="confidential_client"
REDIRECT_URI="http://localhost/callback"

OP_PORT=8080
AUTH_URL="https://localhost:${OP_PORT}/protocol/openid-connect/auth"
TOKEN_URL="https://localhost:${OP_PORT}/protocol/openid-connect/token"

echo
echo "🛰️  Hybrid latency debug (TLS_SIGN=${TLS_SIGN}, JWT_SIGN=${JWT_SIGN})"
echo "────────────────────────────────────────────────────────────────────────────"

# ─── 1) GET /auth → fetch code ───────────────────────────────────────────────
echo
echo "🔗 1) GET /auth → fetch code (with verbose output)"
t0=$(date +%s%3N)

# Build URL
url="${AUTH_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid&state=xyz&nonce=abc"
echo "DEBUG: Running: curl -k -v --connect-timeout 2 -m 5 -D - \"$url\" -o /dev/null"

# Turn off 'exit on error' so we can capture curl's exit code
set +e
resp="$(curl -k -v \
          --connect-timeout 2 \
          -m 5 \
          -D - \
          "$url" \
          -o /dev/null 2>&1)"
curl_rc=$?
set -e

t1=$(date +%s%3N)
echo "DEBUG: curl exit code: $curl_rc"
echo "DEBUG: raw response and verbose logs:"
echo "$resp" | sed 's/^/  /'

if [[ $curl_rc -ne 0 ]]; then
  echo "❌ curl failed (exit code=$curl_rc)"
  echo "--- OP logs ---"
  docker logs "$OP_CONTAINER" --tail 50 || true
  echo "--- RP logs ---"
  docker logs "$RP_CONTAINER" --tail 50 || true
  exit 1
fi

# Parse the code out of the Location header
code="$(echo "$resp" | grep -i '^Location:' | sed -E 's/.*[?&]code=([^& ]+).*/\1/')"
if [[ -z "$code" ]]; then
  echo "❌ Failed to parse code from Location header"
  exit 1
fi
echo "→ Parsed code: $code"
echo "→ GET /auth latency: $((t1 - t0)) ms"

# ─── 2) POST /token → exchange code ─────────────────────────────────────────
echo
echo "🔑 2) POST /token → exchange code (with verbose output)"
t2=$(date +%s%3N)

echo "DEBUG: Running: curl -k -v --connect-timeout 2 -m 5 -X POST \"$TOKEN_URL\" -d grant_type=authorization_code -d code=$code -d redirect_uri=$REDIRECT_URI -d client_id=$CLIENT_ID"

set +e
token_resp="$(curl -k -v \
               --connect-timeout 2 \
               -m 5 \
               -X POST "$TOKEN_URL" \
               -d grant_type=authorization_code \
               -d code="$code" \
               -d redirect_uri="$REDIRECT_URI" \
               -d client_id="$CLIENT_ID" \
               2>&1)"
curl_rc2=$?
set -e

t3=$(date +%s%3N)
echo "DEBUG: curl exit code: $curl_rc2"
echo "DEBUG: raw response and verbose logs:"
echo "$token_resp" | sed 's/^/  /'

if [[ $curl_rc2 -ne 0 ]]; then
  echo "❌ token request failed (exit code=$curl_rc2)"
  echo "--- OP logs ---"
  docker logs "$OP_CONTAINER" --tail 50 || true
  echo "--- RP logs ---"
  docker logs "$RP_CONTAINER" --tail 50 || true
  exit 1
fi

# Try to extract access_token just to ensure it worked
access_token="$(echo "$token_resp" | grep -o '"access_token":[^,]*')"
echo "→ Token response snippet: $access_token"
echo "→ POST /token latency: $((t3 - t2)) ms"

echo
echo "✅ Hybrid latency debug complete."
