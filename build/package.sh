#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SOURCE_DIR="${SCRIPTPATH}/.."

PLATFORM=${1:-ol8-x86_64}

case "${PLATFORM}" in
    ol8|ol8-x86_64)
        ARCH=amd64
        PLATFORM_DIR=ol8/x86_64
        ;;
    ol8-aarch64|ol8-arm64)
        ARCH=arm64
        PLATFORM_DIR=ol8/arm64
        ;;
    ol9|ol9-x86_64)
        ARCH=amd64
        PLATFORM_DIR=ol9/x86_64
        ;;
    ol9-aarch64|ol9-arm64)
        ARCH=arm64
        PLATFORM_DIR=ol9/arm64
        ;;
    debian12|debian12-x86_64)
        ARCH=amd64
        PLATFORM_DIR=debian12/x86_64
        ;;
    debian12-aarch64|debian12-arm64)
        ARCH=arm64
        PLATFORM_DIR=debian12/arm64
        ;;
    ubuntu24|ubuntu24-x86_64)
        ARCH=amd64
        PLATFORM_DIR=ubuntu24/x86_64
        ;;
    ubuntu24-aarch64|ubuntu24-arm64)
        ARCH=arm64
        PLATFORM_DIR=ubuntu24/arm64
        ;;
    *)
        echo "Unsupported package platform: ${PLATFORM}" >&2
        echo "Use debian12-x86_64, debian12-arm64, ol8-x86_64, ol8-arm64, ol9-x86_64, ol9-arm64, ubuntu24-x86_64 or ubuntu24-arm64." >&2
        exit 1
        ;;
esac

if [ ! -e "${SOURCE_DIR}/binaries/${PLATFORM_DIR}/traceroute" ]
then
    if ! "${SCRIPTPATH}/build.sh" --build --clean --platform="${PLATFORM}"
    then
        echo "Failed to build for ${PLATFORM}"
        exit 1
    fi
fi

VERSION=$(awk '{print $NF}' ${SOURCE_DIR}/VERSION)

for PACKAGER in rpm deb
do
    if ! docker run --rm  \
        -v "${SOURCE_DIR}:/work" \
        -w /work \
        -e VERSION=${VERSION} \
        -e ARCH=${ARCH} \
        -e PLATFORM=${PLATFORM} \
        -e PLATFORM_DIR=${PLATFORM_DIR} \
        goreleaser/nfpm:v2.44.0 package --config /work/build/package.yaml --packager ${PACKAGER} --target /work/build/
    then
        echo "Failed to create ${PACKAGER} package"
    fi
done
