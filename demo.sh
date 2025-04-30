#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="confidential_client"
REDIRECT_URI="http://localhost/callback"
AUTH_URL="http://localhost:8080/auth"
TOKEN_URL="http://localhost:8080/token"

# 1) Hit /auth and capture the “code” out of the Location header
t0=$(date +%s%3N)
location=$(curl -s -D - \
  "${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid&state=xyz&nonce=abc" \
  -o /dev/null)

# parse the code param
code=$(echo "$location" | grep -Fi Location: | sed -E 's/.*[&?]code=([^& ]+).*/\1/')
t1=$(date +%s%3N)

# 2) Exchange code for token
token_resp=$(curl -s -X POST "$TOKEN_URL" \
  -d "grant_type=authorization_code" \
  -d "code=$code" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID")
t2=$(date +%s%3N)

# 3) Extract access_token (just to confirm it worked)
access_token=$(echo "$token_resp" | jq -r .access_token)

# 4) Report
echo "→ Code fetch took: $((t1 - t0)) ms"
echo "→ Token exchange took: $((t2 - t1)) ms"
echo "→ access_token prefix: ${access_token:0:8}…"
