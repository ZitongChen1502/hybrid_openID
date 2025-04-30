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
      shared zlib no-docs \
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

# 5) Update ld cache so custom OpenSSL libs are found:
     RUN printf "/usr/local/openssl-3.3/lib\n/usr/local/openssl-3.3/lib64\n/usr/local/lib\n/usr/local/lib64\n" \
     > /etc/ld.so.conf.d/openssl-3.3.conf \
&& ldconfig

# (no other changes until final image)
# ───────────────────────────────────────────────────────────────────

# STAGE 2: final OP image

# ───────────────────────────────────────────────────────────────────

FROM python:3.13-slim



# install runtime & build deps for python-ldap

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libssl3 \
      gcc \
      python3-dev \
      libldap2-dev \
      libsasl2-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy our hybrid-enabled OpenSSL binary and its libs + provider module:

COPY --from=builder /usr/local/openssl-3.3/bin/openssl /usr/local/bin/openssl

COPY --from=builder /usr/local/openssl-3.3/lib /usr/local/openssl-3.3/lib

COPY --from=builder /usr/local/openssl-3.3/lib64 /usr/local/openssl-3.3/lib64

COPY --from=builder /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so \
                   /usr/lib/x86_64-linux-gnu/ossl-modules/


COPY op/op_certs/ServerCerts/ /op_certs/ServerCerts/
                   


# Update loader cache again in final image:

RUN printf "/usr/local/openssl-3.3/lib\n/usr/local/openssl-3.3/lib64\n/usr/local/lib\n/usr/local/lib64\n/usr/lib/x86_64-linux-gnu/ossl-modules\n" \
     > /etc/ld.so.conf.d/openssl-3.3.conf \
&& ldconfig



# Make sure the openssl CLI uses our provider path:

ENV OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules \
   LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib:/usr/local/openssl-3.3/lib64:/usr/local/lib:/usr/local/lib64



WORKDIR /app

COPY op/app/requirements.txt .

RUN pip3 install -r requirements.txt

COPY op/app /app



EXPOSE 8080

CMD ["python3","app.py"]