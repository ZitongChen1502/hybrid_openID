import json

ecdsa = json.load(open('op_certs/JWTKeys/op_jwt_ecdsa.jwk'))
falcon = json.load(open('op_certs/JWTKeys/op_jwt_falcon512.jwk'))

# Mark both as hybrid
for k in (ecdsa, falcon):
    k['alg'] = 'ES256_FALCON512'

jwks = {'keys': [ecdsa, falcon]}

with open('op_certs/JWTKeys/op_hybrid_jwks.json', 'w') as f:
    json.dump(jwks, f, indent=2)

print("✅ op_hybrid_jwks.json created")
