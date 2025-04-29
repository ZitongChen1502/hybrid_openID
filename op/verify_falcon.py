#!/usr/bin/env python3
import base64
import json
import os
import oqs  # requires `pip install liboqs-python`

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)

def main():
    # 1) Make sure TOKEN is set in your shell:
    #    export TOKEN="eyJhbGciOi...<rest of your JWT>"
    token = os.getenv('TOKEN')
    if not token:
        print("Set your ID Token in $TOKEN first.")
        return

    # 2) Load the Falcon-512 JWK JSON you fetched to falcon.jwk
    jwk = json.load(open('falcon.jwk'))
    pub_raw = b64url_decode(jwk['x'])

    # 3) Split JWT into header.payload and signature
    header_payload, sig_b64 = token.rsplit('.', 1)
    data = b64url_decode(header_payload)
    signature = b64url_decode(sig_b64)

    # 4) Verify with liboqs
    with oqs.Signature('Falcon512') as verifier:
        valid = verifier.verify(data, signature, pub_raw)
    print("Falcon-512 signature valid:", valid)

if __name__ == "__main__":
    main()
