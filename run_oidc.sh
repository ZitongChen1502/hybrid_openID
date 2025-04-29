
# 1) Create the network
docker network create oidc-net 2>/dev/null || true

# 2) Tear down old containers
docker rm -f my-op-test my-rp-test 2>/dev/null || true

# 3) Start OP
docker run -d \
  --name my-op-test \
  --network oidc-net \
  -e TLS_SIGN="" \
  -e OP_IP=my-op-test \
  -e RP_IP=localhost \
  -v "$(pwd)/op/op_certs":/op_certs:ro \
  -p 8080:8080 \
  my-op-test

echo "⏳ Waiting for OP…"
sleep 3

echo "→ OP discovery:"
curl -sS http://localhost:8080/.well-known/openid-configuration | jq .issuer
echo

echo "→ Files in OP /op_certs/JWTKeys:"
docker exec my-op-test ls /op_certs/JWTKeys
echo

# 4) Start RP
docker run -d \
  --name my-rp-test \
  --network oidc-net \
  -e OP_IP=my-op-test \
  -e RP_IP=localhost \
  -e JWT_SIGN=falcon512 \
  -e OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules \
  -v /usr/lib/x86_64-linux-gnu/ossl-modules:/usr/lib/x86_64-linux-gnu/ossl-modules:ro \
  -v "$(pwd)/op/op_certs":/op_certs:ro \
  -p 80:80 \
  my-rp-test

echo "⏳ Waiting for RP…"
sleep 3

echo "→ Files in RP /op_certs/JWTKeys:"
docker exec my-rp-test ls /op_certs/JWTKeys
echo

echo "→ RP /auth → HTTP $(curl -s -o /dev/null -w '%{http_code}' http://localhost/auth)"
echo "→ RP callback echo → $(curl -s 'http://localhost/auth/callback?state=xyz&session_state=foo&code=BAR')"
echo

echo "✅ Done."
