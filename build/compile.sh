#!/bin/sh

# This script is run inside the docker container to compile the traceroute binary. It is called by the build.sh script.
# precompiled_openssl is filled by the platform Dockerfile either with a placeholder_file (if openssl3 is disabled) or
# with the compiled openssl3 library for that platform.

set -x

DISABLE_OPENSSL=$1

if [ "$DISABLE_OPENSSL" != "1" ]
then
    cp precompiled_openssl/libcrypto.so.3 /usr/local/lib/libcrypto.so
    cp precompiled_openssl/libssl.so.3 /usr/local/lib/libssl.so
    cp -r precompiled_openssl/openssl /usr/local/include/
fi

cd traceroute
make clean

if [ "$DISABLE_OPENSSL" = "1" ]
then
    make DISABLE_OPENSSL=1
else
    make
fi
