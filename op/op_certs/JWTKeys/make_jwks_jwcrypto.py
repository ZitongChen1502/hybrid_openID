import json
from jwcrypto import jwk

# 1) Load your EC P-256 private key (will extract the public part)
with open("op_jwt_ecdsa.key", "rb") as f:
    ec_pem = f.read()
ec_key = jwk.JWK.from_pem(ec_pem)

# 2) Load your Falcon-512 public key (in PEM or raw format)
# If you only have a .key, extract the public part first:
#   openssl pkey -pubout -in op_jwt_falcon512.key -out op_jwt_falcon512.pub
with open("op_jwt_falcon512.pub", "rb") as f:
    pqc_pem = f.read()
pqc_key = jwk.JWK.from_pem(pqc_pem)

# 3) Export their public JWK dicts
ec_jwk = json.loads(ec_key.export_public())
pqc_jwk = json.loads(pqc_key.export_public())

# 4) Tweak them for hybrid JWT use
for jwk_dict, kid in ((ec_jwk, "ec1"), (pqc_jwk, "falcon1")):
    jwk_dict["alg"] = "ES256_FALCON512"
    jwk_dict["use"] = "sig"
    jwk_dict["kid"] = kid

# 5) Combine and write JWKS
jwks = {"keys": [ec_jwk, pqc_jwk]}
with open("op_hybrid_jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)

print("Wrote op_hybrid_jwks.json with public EC P-256 and Falcon-512 keys")
