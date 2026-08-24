# Cross-compiles an Oracle Linux 8-compatible ARM64 binary from x86_64.
# The ARM64 GNU toolchain is installed from Oracle Linux's public developer
# repository below. OpenSSL is built from source for the target.

FROM oraclelinux:8.10

ARG OPENSSL_VERSION=3.6.2
ARG OPENSSL_SHA256=

ENV SYSROOT=/opt/aarch64-sysroot

COPY oracle-linux-developer.repo /etc/yum.repos.d/ol8_developer.repo

RUN dnf install -y \
        --disablerepo='*' \
        --enablerepo=ol8_developer \
        --enablerepo=ol8_baseos_latest \
        --enablerepo=ol8_appstream \
        binutils-aarch64-linux-gnu \
        gcc-aarch64-linux-gnu \
        cpio \
        dnf-plugins-core \
        make \
        perl \
        perl-IPC-Cmd \
        perl-Time-Piece \
        pkgconf-pkg-config \
        curl \
    && mkdir -p "${SYSROOT}" /tmp/aarch64-rpms \
    && dnf --forcearch=aarch64 \
        --installroot="${SYSROOT}" \
        --releasever=8 \
        --disablerepo='*' \
        --enablerepo=ol8_baseos_latest_aarch64 \
        --setopt=install_weak_deps=False \
        --setopt=module_platform_id=platform:el8 \
        --nogpgcheck \
        --downloadonly \
        --downloaddir=/tmp/aarch64-rpms \
        install glibc-devel glibc-headers kernel-headers libgcc \
    && for rpm in /tmp/aarch64-rpms/*.rpm; do \
         rpm2cpio "${rpm}" | cpio -idm --quiet -D "${SYSROOT}"; \
       done \
    && test -f "${SYSROOT}/usr/include/stdlib.h" \
    && test -f "${SYSROOT}/usr/include/sys/types.h" \
    && command -v aarch64-linux-gnu-gcc \
    && command -v aarch64-linux-gnu-ar \
    && command -v aarch64-linux-gnu-ranlib

RUN command -v pkg-config \
    && mkdir -p /opt/openssl-aarch64 /tmp/openssl-src \
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
