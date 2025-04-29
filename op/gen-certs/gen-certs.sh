#!/usr/bin/env bash
set -xe   # <— prints each command before executing, and exits on any error

# === Debug info ===
OQS_OPENSSL_CMD="${OQS_OPENSSL_CMD:-openssl}"
echo "Using OpenSSL command: $OQS_OPENSSL_CMD"
echo "Modules path:        $OPENSSL_MODULES"
echo "Raw TLS_SIGALG (build arg): '$TLS_SIGALG'"
# TLS_SIGN is mentioned in project README for runtime, may not be present at build time
echo "Raw TLS_SIGN (runtime var): '$TLS_SIGN'"
echo "Raw JWT_SIGN (build arg):   '$JWT_SIGN'"

prefix="op"
serverIP="${OP_IP:-op}"
subjectAltNameType="${SUBJECT_ALT_NAME_TYPE:-DNS}"
WORKING_DIR="${prefix}_certs"
CONF_DIR="/opt/cert-confs" # Assuming this path from Dockerfile COPY

# Prepare all the output dirs
for d in RootCA IntermediaryCAs ServerCerts JWTKeys; do
  mkdir -p "$WORKING_DIR/$d"
done

# Config files
rootconf="$CONF_DIR/openssl_root_conf.cnf"
intermediateconf="$CONF_DIR/openssl_intermediate.cnf"
intermediateExt="$CONF_DIR/IntCA-extensions-x509.cnf"
endcertExt="$CONF_DIR/EndCert-extensions-x509.cnf"

# Only classical CAs here
ca_algos=(rsa ecdsa)

# --- Helper Function for Provider Flags ---
# Returns the necessary provider flags ONLY if OPENSSL_MODULES is set and algo is OQS
get_provider_flags() {
    local algo="$1"
    local flags=""
    # Check if the algorithm is likely an OQS one AND if modules path is set
    # Include known hybrids that need the provider for keygen
    if [[ ! " ${ca_algos[*]} " =~ " $algo " ]] && [[ -n "$OPENSSL_MODULES" ]]; then
        # Correct order: default first, then oqsprovider, with paths
        flags="-provider default -provider-path $OPENSSL_MODULES -provider oqsprovider -provider-path $OPENSSL_MODULES"
    fi
    echo "$flags"
}

# --- Helper Function for Key Generation (Private + Public) ---
generate_key() {
    local algo="$1"
    local keyfile="$2"
    local pubfile="${keyfile%.key}.pub" # Derive public key filename
    # Get flags as a string
    local provider_flags_str=$(get_provider_flags "$algo")

    echo "→ genpkey $algo -> $keyfile"

    case "$algo" in
        rsa)
            "$OQS_OPENSSL_CMD" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keyfile"
            ;;
        ecdsa)
            # Use P-256 curve (prime256v1) common for JWT ES256
            "$OQS_OPENSSL_CMD" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$keyfile"
            ;;
        # Handle OQS and hybrid algorithms known to be supported by genpkey via provider
        dilithium*|falcon*|sphincs*|kyber*|frodo*|p256_falcon512|rsa3072_falcon512|p521_falcon1024)
            # OQS algorithms - pass the flags string directly, let shell parse it
            "$OQS_OPENSSL_CMD" genpkey -algorithm "$algo" -out "$keyfile" $provider_flags_str
            ;;
        *)
            echo "   ERROR: Unknown algorithm '$algo' in generate_key" >&2
            exit 1
            ;;
    esac
    if [ $? -ne 0 ]; then echo "ERROR: Private key generation failed for $algo"; exit 1; fi

    # Generate corresponding public key
    echo "→ pkey -pubout $algo -> $pubfile"
    "$OQS_OPENSSL_CMD" pkey -in "$keyfile" -pubout -out "$pubfile" $provider_flags_str
     if [ $? -ne 0 ]; then
        echo "ERROR: Failed to generate public key for $algo from $keyfile"
        exit 1
    fi
    echo "   Keys generated: $keyfile / $pubfile"
}


# ─── Root CAs ───────────────────────────────────────────────────────────────
echo "=== Generating Root CAs ==="
for algo in "${ca_algos[@]}"; do
  key="$WORKING_DIR/RootCA/${prefix}_rootca_${algo}.key"
  crt="$WORKING_DIR/RootCA/${prefix}_rootca_${algo}.crt"
  provider_flags_str=$(get_provider_flags "$algo") # Empty for classical

  generate_key "$algo" "$key"

  echo "→ Self-sign Root CA ($algo)"
  "$OQS_OPENSSL_CMD" req -x509 -new -nodes \
    -key    "$key" \
    -out    "$crt" \
    -subj   "/CN=OQS Root CA ($algo)" \
    -config "$rootconf" \
    -extensions v3_ca \
    $provider_flags_str \
    -days   3650
  if [ $? -ne 0 ]; then echo "ERROR: Root CA cert generation failed for $algo"; exit 1; fi
done

# ─── Intermediate CAs ────────────────────────────────────────────────────────
echo "=== Generating Intermediate CAs ==="
for algo in "${ca_algos[@]}"; do
  rkey="$WORKING_DIR/RootCA/${prefix}_rootca_${algo}.key"
  rcrt="$WORKING_DIR/RootCA/${prefix}_rootca_${algo}.crt"
  ikey="$WORKING_DIR/IntermediaryCAs/${prefix}_intca_${algo}.key"
  icsr="$WORKING_DIR/IntermediaryCAs/${prefix}_intca_${algo}.csr"
  icrt="$WORKING_DIR/IntermediaryCAs/${prefix}_intca_${algo}.crt"
  bundle="$WORKING_DIR/IntermediaryCAs/bundle_chain_${prefix}_${algo}.crt"
  provider_flags_str=$(get_provider_flags "$algo") # Empty for classical

  generate_key "$algo" "$ikey"

  echo "→ CSR for Intermediate CA ($algo)"
  "$OQS_OPENSSL_CMD" req -new -nodes \
    -key    "$ikey" \
    -out    "$icsr" \
    -subj   "/CN=OQS Intermediate CA ($algo)" \
    -config "$intermediateconf" \
    $provider_flags_str
  if [ $? -ne 0 ]; then echo "ERROR: Intermediate CA CSR generation failed for $algo"; exit 1; fi

  echo "→ Signing Intermediate with Root CA ($algo)"
  # Use provider flags relevant to the signing CA key
  signing_provider_flags_str=$(get_provider_flags "$algo")
  "$OQS_OPENSSL_CMD" x509 -req \
    -in       "$icsr" \
    -CA       "$rcrt" \
    -CAkey    "$rkey" \
    -CAcreateserial \
    -out      "$icrt" \
    -extfile  "$intermediateExt" \
    -extensions v3_intermediate_ca \
    $signing_provider_flags_str \
    -days     1825
  if [ $? -ne 0 ]; then echo "ERROR: Intermediate CA cert signing failed for $algo"; exit 1; fi

  cat "$icrt" "$rcrt" > "$bundle"
  # rm "$icsr" # Optional cleanup
done

# ─── Server Certificate ─────────────────────────────────────────────────────
# choose from TLS_SIGALG build-arg first, then TLS_SIGN runtime var (likely empty at build), else default
serverAlgo="${TLS_SIGALG:-p256_falcon512}"
echo "=== Generating Server Cert for TLS=$serverAlgo ==="
echo "   (Signing with ECDSA Intermediate CA)"
ikey="$WORKING_DIR/IntermediaryCAs/${prefix}_intca_ecdsa.key"
icrt="$WORKING_DIR/IntermediaryCAs/${prefix}_intca_ecdsa.crt"
ibundle="$WORKING_DIR/IntermediaryCAs/bundle_chain_${prefix}_ecdsa.crt" # Bundle used for final chain
sKey="$WORKING_DIR/ServerCerts/${prefix}_server_${serverAlgo}.key"
sCsr="$WORKING_DIR/ServerCerts/${prefix}_server_${serverAlgo}.csr"
sCrt="$WORKING_DIR/ServerCerts/${prefix}_server_${serverAlgo}.crt"
sBundle="$WORKING_DIR/ServerCerts/bundle_chain_${prefix}_${serverAlgo}.crt"

# Check if signing CA files exist
if [ ! -f "$ikey" ] || [ ! -f "$icrt" ]; then
    echo "   ERROR: Intermediate CA key or certificate for signing algorithm ecdsa not found. Cannot sign Server Cert." >&2
    exit 1
fi

# Generate the server key (potentially hybrid)
generate_key "$serverAlgo" "$sKey"

echo "→ CSR for Server Cert"
altName="$subjectAltNameType:$serverIP"
# Get provider flags needed for the specific server key algorithm
server_provider_flags_str=$(get_provider_flags "$serverAlgo")
"$OQS_OPENSSL_CMD" req -new -nodes \
  $server_provider_flags_str \
  -key     "$sKey" \
  -out     "$sCsr" \
  -subj    "/CN=$serverIP" \
  -addext  "subjectAltName=$altName" \
  -config  "$endcertExt"
if [ $? -ne 0 ]; then echo "ERROR: Server CSR generation failed for $serverAlgo"; exit 1; fi

echo "→ Signing Server Cert"
# **** CORRECTED: Use provider flags for the CSR's algorithm ($serverAlgo) ****
# **** (The flags for the signing CA key are not needed here) ****
csr_provider_flags_str=$(get_provider_flags "$serverAlgo")
"$OQS_OPENSSL_CMD" x509 -req \
  $csr_provider_flags_str \
  -in       "$sCsr" \
  -CA       "$icrt" \
  -CAkey    "$ikey" \
  -CAcreateserial \
  -out      "$sCrt" \
  -extfile  "$endcertExt" \
  -extensions usr_cert \
  -days     365
if [ $? -ne 0 ]; then echo "ERROR: Server cert signing failed for $serverAlgo with ecdsa CA"; exit 1; fi

# Create the final bundle including the server cert and the signing CA's bundle
cat "$sCrt" "$ibundle" > "$sBundle"
# rm "$sCsr" # Optional cleanup

# ─── JWT Keys ─────────────────────────────────────────────────────────────────
echo "=== Generating JWT Keys ($JWT_SIGN) ==="
mkdir -p "$WORKING_DIR/JWTKeys"
case "$JWT_SIGN" in
  p256_falcon512)
    generate_key ecdsa    "$WORKING_DIR/JWTKeys/${prefix}_jwt_p256.key"
    generate_key falcon512 "$WORKING_DIR/JWTKeys/${prefix}_jwt_falcon512.key"
    ;;
  rsa)
    generate_key rsa "$WORKING_DIR/JWTKeys/${prefix}_jwt_rsa.key"
    ;;
  ecdsa)
    generate_key ecdsa "$WORKING_DIR/JWTKeys/${prefix}_jwt_p256.key"
    ;;
  # Add other specific supported hybrid or single algorithms here
  *)
    echo "WARNING: Unrecognized or generic JWT_SIGN='$JWT_SIGN', attempting generic keygen..."
    # Ensure the generic algorithm is supported by generate_key
    generate_key "$JWT_SIGN" "$WORKING_DIR/JWTKeys/${prefix}_jwt_${JWT_SIGN}.key"
    ;;
esac

# --- JWKS Generation Placeholder ---
echo "-------------------------------------------------------------------------------------------------------------"
echo "Placeholder for JWKS Generation - Implement this step!"
echo "Example: jose jwk from-pem \"$JWTKeys/${prefix}_jwt_p256.pub\" --alg ES256 --kid p256_key -o \"$JWTKeys/p256.jwk\""
echo "Example: jose jwk from-pem \"$JWTKeys/${prefix}_jwt_falcon512.pub\" --alg FALCON512 --kid falcon_key -o \"$JWTKeys/falcon512.jwk\""
echo "Example: jose jwks merge \"$JWTKeys/p256.jwk\" \"$JWTKeys/falcon512.jwk\" -o \"$JWTKeys/hybrid_jwks.json\""
echo "-------------------------------------------------------------------------------------------------------------"


echo "All certs and keys are in: $WORKING_DIR"
ls -lR "$WORKING_DIR"

