# ───────────────────────────────────────────────────────────────────
# STAGE 1: build OpenSSL-3.3, liboqs + oqs-provider + liboqs-python + generate certs
# ───────────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

# --- Build Arguments ---
ARG OP_IP=op
ARG TLS_SIGALG=p256_falcon512
ARG JWT_SIGN=p256_falcon512

# 1) build essentials + wget/tar
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential cmake git libssl-dev \
      wget tar python3-pip python3-dev findutils binutils perl \
 && rm -rf /var/lib/apt/lists/*

# 1b) Build and install OpenSSL 3.3.0 (skip apps and docs)
WORKDIR /opt/openssl
RUN echo "=== Building OpenSSL 3.3.0 ===" \
 && wget https://www.openssl.org/source/openssl-3.3.0.tar.gz \
 && tar xzf openssl-3.3.0.tar.gz \
 && cd openssl-3.3.0 \
 # Install into /usr/local/openssl-3.3, add no-docs and no-apps
 && ./config \
      --prefix=/usr/local/openssl-3.3 \
      --openssldir=/usr/local/openssl-3.3/ssl \
      shared zlib no-docs no-apps \
 && echo "=== Running make for OpenSSL 3.3.0 ===" \
 && make -j"$(nproc)" \
 && echo "=== Running make install for OpenSSL 3.3.0 ===" \
 && make install_sw \
 && echo "=== Finished OpenSSL 3.3.0 install_sw (no-apps) ==="

RUN mkdir -p /usr/local/openssl-3.3/lib /usr/local/openssl-3.3/lib64

# Figure out whether it's lib or lib64 and write to temp file
RUN if [ -d "/usr/local/openssl-3.3/lib64" ]; then \
       echo "OPENSSL_CUSTOM_LIB_DIR=/usr/local/openssl-3.3/lib64" > /tmp/openssl_env; \
    else \
       echo "OPENSSL_CUSTOM_LIB_DIR=/usr/local/openssl-3.3/lib" > /tmp/openssl_env; \
    fi \
 && cat /tmp/openssl_env

# Load custom lib dir into ENV for subsequent RUN commands in this stage
ENV $(cat /tmp/openssl_env) \
    # Keep custom lib path for linking, but remove custom bin path from PATH
    LD_LIBRARY_PATH=${OPENSSL_CUSTOM_LIB_DIR}:$LD_LIBRARY_PATH \
    OPENSSL_ROOT_DIR=/usr/local/openssl-3.3 \
    # **** ADDED: Define where the provider *will be* installed by step 3 ****
    CUSTOM_MODULES=${OPENSSL_CUSTOM_LIB_DIR}/ossl-modules

# Verify ENV vars are set
RUN echo "--- Builder Environment (Post OpenSSL Build) ---" && \
    echo "PATH=$PATH" && \
    echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" && \
    echo "OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR" && \
    echo "CUSTOM_MODULES=$CUSTOM_MODULES" && \
    echo "OPENSSL_CUSTOM_LIB_DIR=$OPENSSL_CUSTOM_LIB_DIR" && \
    echo "------------------------------------------------"

# 2) Build liboqs against our custom OpenSSL headers/libs
WORKDIR /opt/liboqs
RUN echo "=== Building liboqs ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git . \
 && mkdir build && cd build \
 && cmake \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR} \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_DIST_BUILD=ON .. \
 && make -j"$(nproc)" install \
 && echo "=== liboqs installed ==="

# ensure /usr/local/lib64 always exists so final COPY won't fail
RUN mkdir -p /usr/local/lib64

# 3) Build oqs-provider against custom OpenSSL headers/libs
WORKDIR /opt/oqs-provider
RUN echo "=== Building oqs-provider ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git . \
 && mkdir build && cd build \
 && cmake \
      # Install provider relative to custom OpenSSL prefix
      -DCMAKE_INSTALL_PREFIX=${OPENSSL_ROOT_DIR} \
      -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR} \
      -DCMAKE_PREFIX_PATH=/usr/local .. \
 && make -j"$(nproc)" install \
 && echo "=== Finished oqs-provider install (relative to custom OpenSSL) ==="

# 4) **** UPDATED: Locate the built provider and copy it into the distro’s module path ****
ENV SYSTEM_MODULE_PATH=/usr/lib/x86_64-linux-gnu/ossl-modules
RUN echo "=== Locating and copying oqsprovider.so to system path ===" \
 && PROVIDER_SO="$(find ${OPENSSL_ROOT_DIR} -type f -name oqsprovider.so | head -n 1)" \
 && echo "Found provider at: $PROVIDER_SO" \
 && if [ -z "$PROVIDER_SO" ]; then echo "ERROR: Could not find oqsprovider.so within ${OPENSSL_ROOT_DIR}"; exit 1; fi \
 && mkdir -p ${SYSTEM_MODULE_PATH} \
 && cp "$PROVIDER_SO" ${SYSTEM_MODULE_PATH}/ \
 && echo "=== Done copying provider ===" \
 && ls -l ${SYSTEM_MODULE_PATH}/oqsprovider.so

# 5) Update ld cache so system openssl can find liboqs dependency
# Renumbered from 4.1
RUN echo "=== Updating linker cache for builder stage ===" \
 && printf "/usr/local/lib\n/usr/local/lib64\n${OPENSSL_CUSTOM_LIB_DIR}\n" \
      > /etc/ld.so.conf.d/all-libs-builder.conf \
 && ldconfig \
 && echo "=== Linker cache updated ==="

# 6) Build liboqs-python
WORKDIR /opt/liboqs-python
RUN echo "=== Building liboqs-python ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git . \
 && pip3 install . \
 && echo "=== Finished liboqs-python install ==="

# 7) Generate certs using SYSTEM openssl
WORKDIR /opt
COPY gen-certs/gen-certs.sh   /opt/gen-certs.sh
COPY gen-certs/cert-confs      /opt/cert-confs/
COPY op_certs /op_certs
# Set args as ENV for the script
# OPENSSL_MODULES is already set to the system path
# include OPENSSL_MODULES pointing to where you copied oqsprovider.so
ENV OP_IP=${OP_IP} \
    TLS_SIGALG=${TLS_SIGALG} \
    JWT_SIGN=${JWT_SIGN} \
    OQS_OPENSSL_CMD=/usr/bin/openssl \
    OPENSSL_MODULES=${SYSTEM_MODULE_PATH} \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64:${OPENSSL_CUSTOM_LIB_DIR}

RUN echo "=== Running gen-certs.sh ===" \
 && chmod +x /opt/gen-certs.sh \
 && /opt/gen-certs.sh \
 && echo "=== Finished gen-certs.sh ===" \
 && ls -lR op_certs


# ───────────────────────────────────────────────────────────────────
# STAGE 2: final OP image
# ───────────────────────────────────────────────────────────────────
FROM python:3.13-slim

# Dockerfile


# install your runtime dependencies
RUN pip install flask oic pyOpenSSL oqs

# Create directories
RUN mkdir -p /app /op_certs

# Copy your certs in exactly the path your code expects
COPY /op_certs /op_certs


# Re-declare build args for use in final ENV
ARG OP_IP=op
ARG TLS_SIGALG=p256_falcon512
ARG JWT_SIGN=p256_falcon512


# liboqs libs
COPY --from=builder /usr/local/lib  /usr/local/lib
COPY --from=builder /usr/local/lib64 /usr/local/lib64


# custom OpenSSL libs (needed for liboqs symbols)
COPY --from=builder /usr/local/openssl-3.3/lib  /usr/local/openssl-3.3/lib
COPY --from=builder /usr/local/openssl-3.3/lib64 /usr/local/openssl-3.3/lib64

# OQS provider module
COPY --from=builder \
     /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so \
     /usr/lib/x86_64-linux-gnu/ossl-modules/
# Generated Certs
COPY --from=builder /opt/op_certs           /op_certs
# Python Wrapper source
COPY --from=builder /opt/liboqs-python      /opt/liboqs-python

# Symlink for Python ctypes wrapper
RUN for d in /usr/local/lib /usr/local/lib64; do \
      # Check if the directory exists before trying to link
      if [ -d "$d" ] && [ -f "$d/liboqs.so" ]; then \
        echo "OP Final Stage: Linking liboqs.so in $d"; \
        cd "$d" && \
        ln -sf liboqs.so libliboqs.so && \
        ln -sf liboqs.so libliboqs.a; \
      fi; \
    done

# Update loader cache in final image
# Include custom OpenSSL libs and system module path
RUN printf "/usr/local/lib\n/usr/local/lib64\n/usr/local/openssl-3.3/lib\n/usr/local/openssl-3.3/lib64\n/usr/lib/x86_64-linux-gnu/ossl-modules\n" \
      > /etc/ld.so.conf.d/all-libs.conf \
 && ldconfig

# Install Python wrapper
RUN pip3 install --no-cache-dir /opt/liboqs-python

# Runtime deps (Need libssl3 from system for Python runtime compatibility)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libssl3 gcc python3-dev libldap2-dev libsasl2-dev findutils binutils \
 && rm -rf /var/lib/apt/lists/*

# Runtime environment
# Point to custom OpenSSL libs (for liboqs dep) and system provider path
ENV LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib64:/usr/local/openssl-3.3/lib:/usr/local/lib:/usr/local/lib64:/usr/lib/x86_64-linux-gnu/ossl-modules \
    # Point OPENSSL_MODULES to the system path where provider lives
    OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules \
    # Pass through build-time args to runtime if needed by app.py
    OP_IP=${OP_IP} \
    TLS_SIGN=${TLS_SIGALG} \
    JWT_SIGN=${JWT_SIGN}

WORKDIR /app
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY app /app

EXPOSE 8080
CMD ["python3","app.py"]
