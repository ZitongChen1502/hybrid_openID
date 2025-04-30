#!/usr/bin/env bash
set -euo pipefail

# ─── Helpers ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_HOST_DIR="$SCRIPT_DIR/op/op_certs"

# ─── Configuration ─────────────────────────────────────────────────────────
OP_IMAGE="my-op-test"
RP_IMAGE="my-rp-test"
NETWORK="oidc-net"

TLS_SIGN="kyber512"
JWT_SIGN="falcon512"

CLIENT_ID="confidential_client"
REDIRECT_URI="http://localhost/callback"

OP_CONTAINER="op-pqc-tls"
RP_CONTAINER="rp-test"
OP_HOST="${OP_IMAGE}"
HOST_LOCAL="localhost"
OP_PORT="8080"
RP_PORT="80"

# ─── 1) Cleanup ─────────────────────────────────────────────────────────────
echo "🧹 Cleaning up old containers…"
for C in "$OP_CONTAINER" "$RP_CONTAINER"; do
  docker rm -f "$C" >/dev/null 2>&1 || true
done

echo "⚙️ Releasing host port $OP_PORT if occupied…"
if lsof -i:"$OP_PORT" &>/dev/null; then
  lsof -ti:"$OP_PORT" | xargs -r kill
fi

echo "🔄 Resetting Docker network '$NETWORK'…"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create "$NETWORK"

# ─── 2) Start OP ────────────────────────────────────────────────────────────
echo "🚀 Starting OP container ('$OP_CONTAINER')…"
CONTAINER_ID=$(docker run -d \
  --name "$OP_CONTAINER" \
  --network "$NETWORK" \
  -e TLS_SIGN="$TLS_SIGN" \
  -e JWT_SIGN="$JWT_SIGN" \
  -e OP_IP="$OP_HOST" \
  -e RP_IP="$HOST_LOCAL" \
  -v "$CERTS_HOST_DIR":/op_certs:ro \
  -p "$OP_PORT:$OP_PORT" \
  "$OP_IMAGE" || echo "")

if [[ -z "$CONTAINER_ID" ]]; then
  echo "❌ Failed to start OP container"
  docker logs "$OP_CONTAINER" || true
  exit 1
fi

echo "⏳ Waiting for OP to initialize…"
sleep 3

echo -n "🔐 Verifying server cert & key inside OP… "
docker exec "$OP_CONTAINER" ls -l /op_certs/ServerCerts || true
if docker exec "$OP_CONTAINER" test -f "/op_certs/ServerCerts/bundlecerts_chain_op_${TLS_SIGN}_${OP_HOST}.crt" \
   && docker exec "$OP_CONTAINER" test -f "/op_certs/ServerCerts/op_${TLS_SIGN}_${OP_HOST}.key"; then
  echo "✔ OK"
else
  echo "❌ Cert or key file missing!"
  docker logs "$OP_CONTAINER" --tail 20
  exit 1
fi

echo -n "📜 Verifying JWKS file inside OP… "
docker exec "$OP_CONTAINER" ls -l /op_certs/JWTKeys || true
if docker exec "$OP_CONTAINER" test -f /op_certs/JWTKeys/op_hybrid_jwks.json; then
  echo "✔ OK"
else
  echo "❌ JWKS missing!"
  docker logs "$OP_CONTAINER" --tail 20
  exit 1
fi

# ─── 3) OP discovery smoke-test over HTTPS ────────────────────────────────────
echo -n "🔍 Testing OP discovery at https://localhost:$OP_PORT/.well-known/openid-configuration"

DISC_CODE=""
for i in {1..10}; do
  DISC_CODE=$(
    curl -k \
      --connect-timeout 2 \
      -m 5 \
      -s -o /dev/null \
      -w "%{http_code}" \
      "https://localhost:$OP_PORT/.well-known/openid-configuration" \
    || echo "000"
  )
  echo -n " [$DISC_CODE]"
  if [[ "$DISC_CODE" == "200" ]]; then
    break
  fi
  sleep 1
done
echo

if [[ "$DISC_CODE" != "200" ]]; then
  echo "❌ OP discovery failed (HTTP $DISC_CODE)"
  echo "--- Last OP logs ---"
  docker logs "$OP_CONTAINER" --tail 50 || true
  exit 1
else
  echo "✔ HTTP $DISC_CODE"
fi


 # ─── 4) Start RP ────────────────────────────────────────────────────────────
echo "🚀 Starting RP container ('$RP_CONTAINER')..."
RP_ID=$(docker run -d \
  --name "$RP_CONTAINER" \
  --network "$NETWORK" \
  -e OP_IP="$OP_HOST" \
  -e RP_IP="$HOST_LOCAL" \
  -e JWT_SIGN="$JWT_SIGN" \
  -p "$RP_PORT:$RP_PORT" \
  "$RP_IMAGE" || echo "")

echo "→ RP container ID: $RP_ID"
echo "→ All containers matching '$RP_CONTAINER':"
docker ps -a --filter "name=$RP_CONTAINER" --format "table {{.ID}}\t{{.Status}}"

if [[ -z "$RP_ID" ]]; then
  echo "❌ No RP container was created! Check that image '$RP_IMAGE' exists:"
  docker images | grep "$RP_IMAGE" || true
  exit 1
fi

# If the container exited instantly, catch it here:
RP_STATE=$(docker inspect -f '{{.State.Status}}' "$RP_CONTAINER")
if [[ "$RP_STATE" != "running" ]]; then
  echo "❌ RP container is not running (status=$RP_STATE). Last logs:"
  docker logs "$RP_CONTAINER" --tail 50 || true
  exit 1
fi

echo "⏳ Waiting for RP to initialize..."
sleep 3



# ─── 5) RP /auth smoke-test ─────────────────────────────────────────────────
echo -n "🔁 RP /auth smoke-test… "
# remove -D -, capture only the status code:
AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:$RP_PORT/auth?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&response_type=code&scope=openid&state=xyz&nonce=abc")

if [[ "$AUTH_CODE" != "302" ]]; then
  echo "❌ Unexpected status code: $AUTH_CODE"
  echo "--- RP logs ---"
  docker logs "$RP_CONTAINER" --tail 50 || true
  exit 1
else
  echo "✔ HTTP $AUTH_CODE (302 Found)"
fi


# ─── 6) RP /token (invalid code) ────────────────────────────────────────────
echo "🔄 RP /token smoke-test (invalid code)…"
TOKEN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$RP_PORT/token" \
  -d "grant_type=authorization_code" \
  -d "code=INVALID" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID")
echo "→ HTTP $TOKEN_CODE (expected >= 400)"

echo -e "\n✅ All smoke tests passed."
