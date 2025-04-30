# Author: Frederico Schardong and Fernanda Müller
import os
import ssl
import sys
import json
import logging
import secrets
import subprocess
import base64
from types import SimpleNamespace

from oic.utils.time_util import utc_time_sans_frac
from oic.utils.keyio import build_keyjar
from oic.utils.jwt import JWT
from utils.utils import get_openid_configuration

from flask import Flask, flash, jsonify, redirect, render_template, url_for, request, g, send_file
from werkzeug.serving import run_simple

# SPHICS+256 require us to change this limit
import http.client
http.client._MAXLINE = 6553600

# disable Flask's message on startup
import flask.cli
flask.cli.show_server_banner = lambda *args: None

TLS_SIGN = (os.getenv("TLS_SIGN") or "").lower()
JWT_SIGN = (os.getenv("JWT_SIGN") or "").lower() or "rsa"

OP_IP = os.getenv("OP_IP") or "op"
RP_IP = os.getenv("RP_IP") or "rp"
LOG_LEVEL = os.getenv("LOG_LEVEL") or "CRITICAL"
SAVE_TLS_DEBUG = os.getenv("SAVE_TLS_DEBUG") or True

logger = logging.getLogger("werkzeug")
logger.setLevel(level=LOG_LEVEL)
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

ARG2OQS = {
    "dilithium2": "Dilithium2",
    "dilithium3": "Dilithium3",
    "dilithium5": "Dilithium5",
    "falcon512": "Falcon-512",
    "falcon1024": "Falcon-1024",
    "sphincsshake256128fsimple": "SPHINCS+-SHAKE256-128f-simple",
    "sphincsshake256192fsimple": "SPHINCS+-SHAKE256-192f-simple",
    "sphincsshake256256fsimple": "SPHINCS+-SHAKE256-256f-simple",
    "rsa": "rsa3072",
    "ecdsa": "secp256r1",
}

sub = "0b58dd50-2abc-4a2b-a20b-c405b050e98f"


def b64u(data: bytes) -> str:
    """URL-safe Base64 no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_hybrid_jwt(header: dict, payload: dict, keyfile: str) -> str:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    cmd = [
        os.getenv("OQS_OPENSSL_CMD", "openssl"),
        "pkeyutl", "-sign",
        "-inkey", keyfile,
        "-provider", "default",
        "-provider-path", os.getenv("OPENSSL_MODULES", ""),
        "-provider", "oqsprovider",
        "-provider-path", os.getenv("OPENSSL_MODULES", ""),
        "-pkeyopt", "digest:SHA256",
        "-rawin"
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sig, _ = proc.communicate(f"{h}.{p}".encode())  # now pkeyutl will SHA256-hash this
    if proc.returncode != 0:
        raise RuntimeError("Hybrid sign failed")
    return f"{h}.{p}.{b64u(sig)}"



def set_global_constants(tls_sign, jwt_sign):
    global TLS_SIGN, JWT_SIGN, METHOD, KEY_TYPE, KEYJAR, SERVER_ADDRESS

    TLS_SIGN = tls_sign if tls_sign else TLS_SIGN
    JWT_SIGN = jwt_sign if jwt_sign else JWT_SIGN

    if TLS_SIGN not in ["rsa", "ecdsa"]:
        os.environ["TLS_DEFAULT_GROUPS"] = "kyber512"

    METHOD = "https" if TLS_SIGN else "http"
    SERVER_ADDRESS = f"{METHOD}://{OP_IP}:8080/"

    KEY_TYPE = "PQC" if JWT_SIGN not in ["rsa", "ecdsa"] else JWT_SIGN.upper()

    if KEY_TYPE == "PQC":
        # load hybrid JWKS so we know the kid
        jwks = json.load(open("/op_certs/JWTKeys/op_hybrid_jwks.json"))
        kid0 = jwks["keys"][0]["kid"]
        # stub a minimal KeyJar for kid lookup
        KEYJAR = SimpleNamespace(get=lambda use: [SimpleNamespace(kid=kid0)])
    elif JWT_SIGN == "rsa":
        _, KEYJAR, _ = build_keyjar(
            [
                {
                    "type": "CryptographyRSA",
                    "alg": "CryptographyRSA",
                    "key": f"/op_certs/JWTKeys/op_rsa.key",
                    "use": ["sig"],
                }
            ]
        )
    else:
        _, KEYJAR, _ = build_keyjar(
            [
                {
                    "type": "CryptographyECDSA",
                    "alg": "CryptographyECDSA",
                    "key": "",
                    "use": ["sig"],
                }
            ]
        )


set_global_constants(TLS_SIGN, JWT_SIGN)

# set to True to inform that the app needs to be re-created
to_reload = False

class AppReloader(object):
    def __init__(self, create_app):
        self.create_app = create_app
        self.app = create_app()

    def get_application(self):
        global to_reload
        if to_reload:
            self.app = self.create_app()
            to_reload = False
        return self.app

    def __call__(self, environ, start_response):
        app = self.get_application()
        return app(environ, start_response)

REQUEST_LENGTH = {}

def get_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

    @app.before_request
    def gather_request_data():
        g.path = request.path

    @app.after_request
    def test(response):
        key = g.path.split("/")[-1]
        if key != "get_requests_length" and ".css" not in key and ".js" not in key:
            key = "Total response size for the OP request: " + key
            REQUEST_LENGTH[key] = REQUEST_LENGTH.get(key, 0) + int(response.content_length or 0)
        return response

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def auth_realms_post_quantum():
        config = json.loads(get_openid_configuration(METHOD, OP_IP))
        config["id_token_signing_alg_values_supported"].append("ES256_FALCON512")
        return jsonify(config)


    @app.route("/protocol/openid-connect/auth", methods=["GET"])
    def idp_pqc_auth_get():
        state = request.args.get("state")
        return render_template("auth.html", state=state)

    @app.route("/protocol/openid-connect/auth", methods=["POST"])
    def idp_pqc_auth_post():
        state = request.form.get("state") or request.args.get("state")
        session_state = "a6480a0f-bb38-4c7a-9908-20f8608e1e48"
        code = "a34b69e9-39af-4301-bf75-de6badb92823.a6480a0f-bb38-4c7a-9908-20f8608e1e48.39fecc"
        return redirect(
            f"{METHOD}://{RP_IP}/auth/callback?state={state}&session_state={session_state}&code={code}",
            code=303,
        )

    @app.route("/protocol/openid-connect/token", methods=["GET", "POST"])
    def idp_pqc_token():
        request.data  # workaround for Flask bug
        iss = SERVER_ADDRESS
        token_type = "Bearer"
        session_state = secrets.token_urlsafe()
        exp = utc_time_sans_frac() + 100000

        kid = KEYJAR.get("sig")[0].kid

        # --- HYBRID JWT PATH ---
        if KEY_TYPE == "PQC":
            # common payload for all three tokens
            def make_payload(aud, typ):
                return {
                    "iss": iss,
                    "sub": sub,
                    "aud": aud,
                    "exp": exp,
                    "iat": utc_time_sans_frac(),
                    "typ": typ,
                    "nonce": secrets.token_urlsafe(),
                    "session_state": session_state,
                }

            # hybrid: use our openssl wrapper
            header = {"alg": "ES256_FALCON512", "kid": KEYJAR.get("sig")[0].kid}
            payload = dict(
                iss=iss, sub=sub, aud="account", exp=exp, typ=token_type,
                nonce=secrets.token_urlsafe(), session_state=session_state,
                iat=utc_time_sans_frac(),
            )
            access_token = sign_hybrid_jwt(header, payload, f"/op_certs/JWTKeys/op_jwt_{JWT_SIGN}.key")
            refresh_token = sign_hybrid_jwt(header, payload, f"/op_certs/JWTKeys/op_jwt_{JWT_SIGN}.key")
            id_token = sign_hybrid_jwt(header, payload, f"/op_certs/JWTKeys/op_jwt_{JWT_SIGN}.key")

        else:
            # classical JWT
            if JWT_SIGN == "rsa":
                sign_alg = "CryptographyRSA"
            else:
                sign_alg = "CryptographyECDSA"
                access_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
                kid=kid, iss=iss, sub=sub, aud="account",
                exp=exp, typ=token_type, nonce=secrets.token_urlsafe(),
                session_state=session_state, iat=utc_time_sans_frac(),
            )
            refresh_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
                kid=kid, iss=iss, sub=sub, aud="account",
                exp=exp * 2, typ="refresh_token", nonce=secrets.token_urlsafe(),
                session_state=session_state, iat=utc_time_sans_frac(),
            )
            id_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
                kid=kid, iss=iss, sub=sub, aud="python",
                exp=exp, iat=utc_time_sans_frac(),
            )

        return {
            "access_token": access_token,
            "expires_in": 3656500,
            "refresh_expires_in": 18546400,
            "refresh_token": refresh_token,
            "token_type": token_type,
            "id_token": id_token,
            "not-before-policy": 0,
            "session_state": "",
            "scope": "openid email profile",
        }

    @app.route("/protocol/openid-connect/certs", methods=["GET"])
    def idp_pqc_certs():
        jwks = json.load(open("/op_certs/JWTKeys/op_hybrid_jwks.json"))
        # force the hybrid alg
        for jwk in jwks["keys"]:
            jwk["alg"] = "ES256_FALCON512"
        return jsonify(jwks)


    @app.route("/protocol/openid-connect/userinfo", methods=["POST"])
    def idp_pqc_userinfos():
        return {
            "sub": sub,
            "email_verified": False,
            "name": "Fernanda Larissa Müller",
            "preferred_name": "teste",
            "given_name": "Fernanda",
            "family_name": "Muller",
            "email": "teste@gmail",
        }

    @app.route("/protocol/openid-connect/logout", methods=["POST"])
    def idp_pqc_logout():
        return redirect(
            request.args.get("post_logout_redirect_uri")
            or request.form.get("post_logout_redirect_uri")
        )

    @app.route("/get_requests_length", methods=["GET"])
    def get_requests_length():
        global REQUEST_LENGTH
        out = dict(REQUEST_LENGTH)
        REQUEST_LENGTH = {}
        return out

    @app.route("/reload", methods=["GET"])
    def reload():
        set_global_constants(TLS_SIGN, request.args.get("JWT_SIGN"))
        global to_reload
        to_reload = True
        logger.info(f"\nRELOADING... now using TLS={TLS_SIGN} and JWT={JWT_SIGN}\n")
        return "ok"

    return app

if __name__ == "__main__":
    if TLS_SIGN:
        keylog = f"/app/tls_debug/TLS={TLS_SIGN}.tls_debug"
        if os.path.exists(keylog):
            os.remove(keylog)

        sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslContext.minimum_version = ssl.TLSVersion.TLSv1_3

        cert_path = f"/op_certs/ServerCerts/bundlecerts_chain_op_{TLS_SIGN}_{OP_IP}.crt"
        key_path  = f"/op_certs/ServerCerts/op_{TLS_SIGN}_{OP_IP}.key"
        
        sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # ─── DEBUG: dump what we're about to load ────────────────────────
        import os, sys
        print("🔍 [DEBUG] cert_path =", cert_path, file=sys.stderr)
        print("🔍 [DEBUG] key_path  =", key_path,  file=sys.stderr)
        try:
            print("🔍 [DEBUG] /op_certs/ServerCerts contains:", os.listdir("/op_certs/ServerCerts"), file=sys.stderr)
        except Exception as e:
            print("🔍 [DEBUG] could not list /op_certs/ServerCerts:", e, file=sys.stderr)

        sslContext.load_cert_chain(certfile=cert_path, keyfile=key_path)



        # only set the classical curve; OQS provider will enable Kyber512 via TLS_DEFAULT_GROUPS
        sslContext.set_ecdh_curve("prime256v1")


        if SAVE_TLS_DEBUG:
            sslContext.keylog_filename = keylog
    else:
        sslContext = None

    run_simple("0.0.0.0", 8080, AppReloader(get_app), ssl_context=sslContext)
