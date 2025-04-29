docker rm -f my-op-test my-rp-test 2>/dev/null || true
docker run -d \
  --name my-op-test \
  --network oidc-net \
  -e TLS_SIGN="" \
  -e OP_IP=localhost \
  -e RP_IP=localhost \
  -v "$(pwd)/op/op_certs":/op_certs:ro \
  -p 8080:8080 \
  my-op-test

sleep 3

docker run -d \
  --name my-rp-test \
  --network oidc-net \
  -e OP_IP=localhost \
  -e RP_IP=localhost \
  -e JWT_SIGN=falcon512 \
  -e OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules \
  -v /usr/lib/x86_64-linux-gnu/ossl-modules:/usr/lib/x86_64-linux-gnu/ossl-modules:ro \
  -v "$(pwd)/op/op_certs":/op_certs:ro \
  -p 80:80 \
  my-rp-test

sleep 3