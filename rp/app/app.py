import os
import ssl
import json
import base64
import subprocess
import requests
from types import SimpleNamespace
from flask import Flask, request, redirect, session, url_for, jsonify

# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------
tls_sign = os.getenv('TLS_SIGN', '').lower()
jwt_sign = os.getenv('JWT_SIGN', 'rsa').lower()

OP_IP = os.getenv('OP_IP', 'op')
RP_IP = os.getenv('RP_IP', 'localhost')
METHOD = 'https' if tls_sign else 'http'
SERVER_ADDRESS = f"{METHOD}://{OP_IP}:8080"
OP_ISSUER = os.getenv('OP_ISSUER', SERVER_ADDRESS)

# -------------------------------------------------------------------------
# KeyJar Stub for Hybrid or RSA/ECDSA
# -------------------------------------------------------------------------
ARG2OQS = {
    'dilithium2': 'Dilithium2',
    'dilithium3': 'Dilithium3',
    'dilithium5': 'Dilithium5',
    'falcon512': 'Falcon-512',
    'falcon1024': 'Falcon-1024',
    'sphincsshake256128fsimple': 'SPHINCS+-SHAKE256-128f-simple',
    'sphincsshake256192fsimple': 'SPHINCS+-SHAKE256-192f-simple',
    'sphincsshake256256fsimple': 'SPHINCS+-SHAKE256-256f-simple',
}

if jwt_sign not in ['rsa', 'ecdsa']:
    # Hybrid mode: stub KEYJAR to extract the 'kid' from OP's JWKS
    jwks = json.load(open('op_hybrid_jwks.json'))
    kid = jwks['keys'][0]['kid']
    KEYJAR = SimpleNamespace(get=lambda use: [SimpleNamespace(kid=kid)])
else:
    # RSA or ECDSA: load real KeyJar
    from oic.utils.keyio import build_keyjar

    if jwt_sign == 'rsa':
        _, KEYJAR, _ = build_keyjar([
            {'type': 'RSA', 'alg': 'RS256', 'key': '/path/to/rp_rsa_pub.pem', 'use': ['sig']}
        ])
    else:
        _, KEYJAR, _ = build_keyjar([
            {'type': 'EC', 'alg': 'ES256', 'key': '/path/to/rp_ec_pub.pem', 'use': ['sig']}
        ])

# -------------------------------------------------------------------------
# Hybrid JWT verification helper
# -------------------------------------------------------------------------
import tempfile
import json
import base64
import subprocess
import os

def verify_hybrid_jwt(token: str, pubkey_path: str) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    # Reconstruct the signed message and raw signature
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = base64.urlsafe_b64decode(sig_b64 + "==")

    # Use temp files so pkeyutl can read them
    with tempfile.NamedTemporaryFile() as msgf, tempfile.NamedTemporaryFile() as sigf:
        msgf.write(msg)
        msgf.flush()
        sigf.write(sig)
        sigf.flush()

        cmd = [
            "openssl", "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey", pubkey_path,
            "-provider", "default",
            "-provider-path", os.getenv("OPENSSL_MODULES", ""),
            "-provider", "oqsprovider",
            "-provider-path", os.getenv("OPENSSL_MODULES", ""),
            "-pkeyopt", "digest:SHA256",
            "-rawin",
            "-in", msgf.name,
            "-sigfile", sigf.name,
        ]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise ValueError("Hybrid JWT signature verification failed:\n" + err.decode())

    # If we get here, signature is valid
    return json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))


# -------------------------------------------------------------------------
# Flask RP Application
# -------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-me')

@app.route('/')
def index():
    return 'RP Home'

@app.route('/auth')
def auth():
    redirect_uri = url_for('callback', _external=True)
    auth_url = (
        f"{OP_ISSUER}/protocol/openid-connect/auth"
        f"?response_type=code&client_id=rp&redirect_uri={redirect_uri}&scope=openid"
    )
    return redirect(auth_url)

@app.route('/auth/callback')
def callback():
    code = request.args.get('code')
    token_resp = requests.post(
        f"{OP_ISSUER}/protocol/openid-connect/token",
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': url_for('callback', _external=True),
            'client_id': 'rp',
        }
    ).json()

    id_token = token_resp.get('id_token')
    if jwt_sign not in ['rsa', 'ecdsa']:
        payload = verify_hybrid_jwt(id_token, '/op_certs/JWTKeys/op_jwt_pqc_pub.pem')
    else:
        from oic.utils.jwt import JWT
        sign_alg = 'RS256' if jwt_sign == 'rsa' else 'ES256'
        payload = JWT(KEYJAR, verify=True, sign_alg=sign_alg).unpack(id_token)

    session['user'] = payload
    return jsonify(payload)

@app.route('/userinfo')
def userinfo():
    if 'user' not in session:
        return redirect(url_for('auth'))
    return jsonify(session['user'])

if __name__ == '__main__':
    # Listen on port 80 so `curl localhost/auth` works without specifying port
    app.run(host='0.0.0.0', port=80)
