# Cross-compiles a Debian 12-compatible ARM64 binary from x86_64.
# The ARM64 GNU toolchain and target glibc headers are provided by Debian's
# cross-toolchain packages. OpenSSL is built from source for the target.
FROM debian:12

ARG OPENSSL_VERSION=3.6.2
ARG OPENSSL_SHA256=

# Debian's cross compiler uses /usr/aarch64-linux-gnu as its target sysroot,
# while retaining the normal Debian cross-toolchain search paths.
ENV SYSROOT=/

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binutils-aarch64-linux-gnu \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        linux-libc-dev-arm64-cross \
        ca-certificates \
        curl \
        make \
        perl \
        pkg-config \
        xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && test -f /usr/aarch64-linux-gnu/include/stdlib.h \
    && test -f /usr/aarch64-linux-gnu/include/sys/types.h \
    && command -v aarch64-linux-gnu-gcc \
    && command -v aarch64-linux-gnu-ar \
    && command -v aarch64-linux-gnu-ranlib \
    && printf '#include <stdlib.h>\n#include <sys/types.h>\n' | \
       aarch64-linux-gnu-gcc --sysroot="${SYSROOT}" -x c -fsyntax-only -

RUN mkdir -p /opt/openssl-aarch64 /tmp/openssl-src \
    && curl -fsSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" \
        -o "/tmp/openssl-${OPENSSL_VERSION}.tar.gz" \
    && if [ -n "${OPENSSL_SHA256}" ]; then \
         echo "${OPENSSL_SHA256}  /tmp/openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c -; \
       fi \
    && tar -xzf "/tmp/openssl-${OPENSSL_VERSION}.tar.gz" -C /tmp/openssl-src \
    && cd "/tmp/openssl-src/openssl-${OPENSSL_VERSION}" \
    && CFLAGS="--sysroot=${SYSROOT}" \
       LDFLAGS="--sysroot=${SYSROOT}" \
       ./Configure linux-aarch64 \
        --cross-compile-prefix=aarch64-linux-gnu- \
        --prefix=/opt/openssl-aarch64 \
        --libdir=lib \
        shared no-tests \
    && make -j"$(nproc)" \
    && make install_sw \
    && test -f /opt/openssl-aarch64/lib/libssl.so.3 \
    && test -f /opt/openssl-aarch64/lib/libcrypto.so.3 \
    && test -f /opt/openssl-aarch64/lib/pkgconfig/openssl.pc

RUN mkdir -p /traceroute
ADD libsupp /traceroute/libsupp/
ADD include /traceroute/include
ADD traceroute /traceroute/traceroute/
ADD Makefile /traceroute/
ADD VERSION /traceroute/
ADD compile.sh /

ENV CROSS_COMPILE=aarch64-linux-gnu-
ENV OPENSSL_ROOT=/opt/openssl-aarch64

RUN chmod +x /compile.sh \
    && /compile.sh aarch64
