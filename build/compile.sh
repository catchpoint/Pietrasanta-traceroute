#!/bin/sh
set -eu

# This script is run inside the docker container to compile the traceroute binary. It is called by the build.sh script.

TARGET_ARCH=${1:-x86_64}

cd /traceroute
make clean

case "${TARGET_ARCH}" in
    x86_64)
        make traceroute
        ;;
    aarch64)
        # here we assume that this script is run on x86_64 host and we are cross-compiling for ARM64 target
        # so we need to compile openssl too (can't install from package manager because we are cross-compiling)
        : "${CROSS_COMPILE:=aarch64-linux-gnu-}"
        : "${SYSROOT:?SYSROOT must point to the target sysroot}"
        : "${OPENSSL_ROOT:?OPENSSL_ROOT must point to the target OpenSSL installation}"

        # Ensure pkg-config returns ARM64 OpenSSL flags rather than host flags.
        export PKG_CONFIG_LIBDIR="${OPENSSL_ROOT}/lib/pkgconfig"
        if ! pkg-config --exists openssl3 2>/dev/null && \
           ! pkg-config --exists openssl 2>/dev/null; then
            echo "Target OpenSSL pkg-config metadata was not found below ${OPENSSL_ROOT}" >&2
            exit 1
        fi

        make traceroute \
            CROSS="${CROSS_COMPILE}" \
            CFLAGS="--sysroot=${SYSROOT} -g -Wall -std=c99 -O0" \
            LDFLAGS="--sysroot=${SYSROOT} -g"
        ;;
    *)
        echo "Unsupported target architecture: ${TARGET_ARCH}" >&2
        exit 1
        ;;
esac
