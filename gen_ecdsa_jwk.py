from jwcrypto import jwk
import json, os

# Generate a new P-256 EC key
key = jwk.JWK(generate="EC", curve="P-256")
# Export as a Python dict
jwk_dict = key.export(private_key=True, as_dict=True)

# Tag it as our hybrid alg
jwk_dict["alg"] = "ES256_FALCON512"

# Ensure the directory exists
os.makedirs("op_certs/JWTKeys", exist_ok=True)
# Write it out
with open("op_certs/JWTKeys/op_jwt_ecdsa.jwk", "w") as f:
    json.dump(jwk_dict, f, indent=2)

print("✅ ECDSA JWK written to op_certs/JWTKeys/op_jwt_ecdsa.jwk")
