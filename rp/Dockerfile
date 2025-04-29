##############################################################################
# Stage 1: Build PQ libs + provider + Python wrapper + generate cert
##############################################################################
FROM ubuntu:22.04 AS builder

ARG RP_IP
ARG TLS_SIGALG=p256_falcon512

# 1) Build tools + OpenSSL + Python build deps
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential cmake git libssl-dev openssl \
      python3-dev python3-pip findutils \
    && rm -rf /var/lib/apt/lists/*

# 2) liboqs
WORKDIR /opt/liboqs
RUN echo "=== Building liboqs ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git . \
 && mkdir build && cd build \
 && cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_DIST_BUILD=ON .. \
 && make -j$(nproc) install \
 && echo "=== Finished liboqs install ==="

# 3) oqs-provider
WORKDIR /opt/oqs-provider
RUN echo "=== Building oqs-provider ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git . \
 && mkdir build && cd build \
 && cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
         -DCMAKE_PREFIX_PATH=/usr/local .. \
 && make -j$(nproc) install \
 && echo "=== Finished oqs-provider install ===" \
 && echo "Installed provider module at:" \
 && find /usr/lib/x86_64-linux-gnu/ossl-modules -name oqsprovider.so

# 3.1) Update linker cache so liboqs.so.7 is visible
RUN printf "/usr/local/lib\n/usr/local/lib64\n" \
      > /etc/ld.so.conf.d/liboqs-builder.conf \
 && ldconfig

# 4) liboqs-python
WORKDIR /opt/liboqs-python
RUN echo "=== Building liboqs-python ===" \
 && git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git . \
 && pip3 install . \
 && echo "=== Finished liboqs-python install ==="

# 5) Generate one hybrid certificate
ENV OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules

RUN echo "=== Generating RP certificate using $TLS_SIGALG ===" \
 && mkdir -p /rp_certs \
 && openssl genpkey \
      -provider default \
      -provider-path $OPENSSL_MODULES \
      -provider oqsprovider \
      -algorithm $TLS_SIGALG \
      -out /rp_certs/rp.key \
 && openssl req -x509 \
      -provider default \
      -provider-path $OPENSSL_MODULES \
      -provider oqsprovider \
      -new -key /rp_certs/rp.key \
      -out /rp_certs/rp.crt \
      -days 365 \
      -subj "/CN=rp" \
 && ls -l /rp_certs

##############################################################################
# Stage 2: Final RP image
##############################################################################
FROM python:3.10-slim

# 1) Copy PQ-enabled OpenSSL + libs
COPY --from=builder /usr/local /usr/local

# 2) Copy OQS provider modules
COPY --from=builder /usr/lib/x86_64-linux-gnu/ossl-modules \
                     /usr/lib/x86_64-linux-gnu/ossl-modules

# 3) Symlink liboqs for ctypes
RUN for d in /usr/local/lib /usr/local/lib64; do \
      if [ -f "$d/liboqs.so" ]; then \
        cd "$d" && ln -sf liboqs.so libliboqs.so && ln -sf liboqs.so libliboqs.a; \
      fi; \
    done

# 4) Update linker cache in final image
RUN printf "/usr/local/lib\n/usr/local/lib64\n/usr/lib/x86_64-linux-gnu\n" \
      > /etc/ld.so.conf.d/liboqs.conf \
 && ldconfig

# 5) Install Python wrapper
COPY --from=builder /opt/liboqs-python /opt/liboqs-python
RUN pip3 install --no-cache-dir /opt/liboqs-python

# 6) Copy generated certificates
COPY --from=builder /rp_certs /rp_certs

# 7) Runtime environment variables
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
ENV OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules

# 8) Install runtime dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libssl3 gcc python3-dev libldap2-dev libsasl2-dev findutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/post-quantum-pyjwkest /app/post-quantum-pyjwkest
ENV JWT_SIGN=es256_falcon512
# default JWT_SIGN to p256_falcon512 (so KEY_TYPE → "PQC")
ENV TLS_SIGALG="" 


COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY app /app

EXPOSE 8080
CMD ["python3","app.py"]
