#!/usr/bin/env bash
set -euo pipefail

# ─── 0) Algorithm args ───────────────────────────────────────────────────────
TLS_SIGN=${1:-kyber512}
JWT_SIGN=${2:-falcon512}

# ─── 1) Vars ─────────────────────────────────────────────────────────────────
OP_IMAGE="my-op-test"
RP_IMAGE="my-rp-test"
NETWORK="oidc-net"

OP_CONTAINER="op-pqc-tls"
RP_CONTAINER="rp-test"
HOST="localhost"

OP_PORT=8080
RP_PORT=80

CLIENT_ID="confidential_client"
REDIRECT_URI="http://$HOST/callback"

# RP’s redirect endpoint (no TLS):
RP_AUTH="http://$HOST:$RP_PORT/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid&state=xyz&nonce=abc"
# OP’s token endpoint (TLS):
OP_TOKEN="https://$HOST:$OP_PORT/protocol/openid-connect/token"

# Where your certs & JWKS live:
CERTS_HOST_DIR="$PWD/op/op_certs"

# ─── 2) Cleanup ───────────────────────────────────────────────────────────────
echo "🧹 Cleaning up old OP/RP & network…"
docker rm -f "$OP_CONTAINER" "$RP_CONTAINER" >/dev/null 2>&1 || true

if lsof -i:"$OP_PORT" &>/dev/null; then
  lsof -ti:"$OP_PORT" | xargs -r kill
fi

docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create "$NETWORK"

# ─── 3) Start OP (hybrid TLS+JWT) ─────────────────────────────────────────────
echo "🚀 Launching OP (TLS=$TLS_SIGN, JWT=$JWT_SIGN)…"
docker run -d \
  --name "$OP_CONTAINER" \
  --network "$NETWORK" \
  -e TLS_SIGN="$TLS_SIGN" \
  -e JWT_SIGN="$JWT_SIGN" \
  -e OP_IP="$OP_IMAGE" \
  -e RP_IP="$HOST" \
  -v "${CERTS_HOST_DIR}":/op_certs:ro \
  -p "${OP_PORT}:${OP_PORT}" \
  "$OP_IMAGE" >/dev/null

echo "⏳ Waiting for OP to come up…"
sleep 3

# ─── 4) Start RP (for auth redirect) ─────────────────────────────────────────
echo "🚀 Launching RP…"
docker run -d \
  --name "$RP_CONTAINER" \
  --network "$NETWORK" \
  -e OP_IP="$OP_IMAGE" \
  -e RP_IP="$HOST" \
  -e JWT_SIGN="$JWT_SIGN" \
  -p "${RP_PORT}:${RP_PORT}" \
  "$RP_IMAGE" >/dev/null

echo "⏳ Waiting for RP to come up…"
sleep 3

# ─── 5) Measure RP /auth → 302 with code ─────────────────────────────────────
echo
echo "1) RP /auth → fetch code"
t0=$(date +%s%3N)
HTTP_AUTH=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 -m 5 "$RP_AUTH")
t1=$(date +%s%3N)

echo "→ status: $HTTP_AUTH"
echo "→ RP /auth latency: $((t1 - t0)) ms"

# ─── 6) Measure OP /token → 4xx (invalid code) ─────────────────────────────
echo
echo "2) OP /token → exchange code"
t2=$(date +%s%3N)
HTTP_TOKEN=$(curl -k -s -o /dev/null -w '%{http_code}' --connect-timeout 2 -m 5 -X POST "$OP_TOKEN" \
  -d grant_type=authorization_code \
  -d code=INVALID \
  -d redirect_uri="$REDIRECT_URI" \
  -d client_id="$CLIENT_ID")
t3=$(date +%s%3N)

echo "→ status: $HTTP_TOKEN"
echo "→ OP /token latency: $((t3 - t2)) ms"

echo
echo "✅ Hybrid latency test complete."
