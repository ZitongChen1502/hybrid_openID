#!/usr/bin/env bash

# 1) Hybrid TLS check inside OP container
echo
echo "🔒 Checking hybrid TLS KEM (P-256+Kyber512) inside OP container..."
docker exec op-pqc-tls openssl s_client \
  -connect 0.0.0.0:8080 \
  -tls1_3 \
  -curves P-256+Kyber512 \
  -msg </dev/null 2>&1 \
  | grep -E "ServerKeyShare|KEX group|P-256" \
  || echo "(no hybrid key-share line found)"

# 2) OIDC flow through RP
echo
echo "🔑 Hitting RP → /auth"
curl -s -D - \
  "http://localhost/auth?client_id=confidential_client&redirect_uri=http://localhost/callback&response_type=code&scope=openid&state=xyz" \
  -o /dev/null
echo

echo "↪  Callback → /auth/callback"
curl -s -D - \
  "http://localhost/auth/callback?state=xyz&session_state=foo&code=BAR" \
  -o /dev/null
echo

echo "🔄 Exchanging code → /token"
curl -s -D - -X POST http://localhost/token \
  -d "grant_type=authorization_code" \
  -d "code=BAR" \
  -d "redirect_uri=http://localhost/callback" \
  -d "client_id=confidential_client" \
  -o /dev/null
echo

echo "✅ test_hybrid_oidc.sh complete."
