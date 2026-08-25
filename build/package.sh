#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SOURCE_DIR="${SCRIPTPATH}/.."

usage()
{
    echo "Usage: $0 [--platform=<platform>] [--arch=<architecture>]"
    echo "  --platform: ol8, ol9, debian12 or ubuntu24 (default: ol8)"
    echo "  --arch: x86_64 or arm64 (default: x86_64)"
}

PLATFORM=ol8
ARCH=x86_64

if ! args=$(getopt -o '' --long platform:,arch:,help -n 'invalid arguments' -- "$@"); then
    usage >&2
    exit 2
fi

eval set -- "$args"

while true; do
    case "$1" in
        --platform)
            PLATFORM=$2; shift 2 ;;
        --arch)
            ARCH=$2; shift 2 ;;
        --help)
            usage
            exit 0 ;;
        --)
            shift
            break ;;
        *)
            echo "Internal error!" >&2
            exit 2 ;;
    esac
done

if [ "$#" -ne 0 ]; then
    echo "Unexpected positional argument: $1" >&2
    usage >&2
    exit 2
fi

case "${PLATFORM}" in
    ol8|ol9|debian12|ubuntu24)
        ;;
    *)
        echo "Unsupported package platform: ${PLATFORM}" >&2
        echo "Use ol8, ol9, debian12 or ubuntu24." >&2
        exit 1
        ;;
esac

case "${ARCH}" in
    x86_64)
        PACKAGE_ARCH=amd64
        ;;
    arm64)
        PACKAGE_ARCH=arm64
        ;;
    *)
        echo "Unsupported package architecture: ${ARCH}. Use x86_64 or arm64." >&2
        exit 1
        ;;
esac

PLATFORM_DIR="${PLATFORM}/${ARCH}"

if [ ! -e "${SOURCE_DIR}/binaries/${PLATFORM_DIR}/traceroute" ]
then
    if ! "${SCRIPTPATH}/build.sh" --build --clean --platform="${PLATFORM}" --arch="${ARCH}"
    then
        echo "Failed to build for ${PLATFORM}"
        exit 1
    fi
fi

VERSION=$(awk '{print $NF}' ${SOURCE_DIR}/VERSION)

for PACKAGER in rpm deb
do
    if ! mkdir -p dist/${PLATFORM}
    then
        echo "Failed to create directory dist/${PLATFORM}"
        exit 1
    fi
    
    if ! docker run --rm  \
        -v "${SOURCE_DIR}:/work" \
        -w /work \
        -e VERSION=${VERSION} \
        -e ARCH=${PACKAGE_ARCH} \
        -e PLATFORM=${PLATFORM} \
        -e PLATFORM_DIR=${PLATFORM_DIR} \
        goreleaser/nfpm:v2.44.0 package --config /work/build/package.yaml --packager ${PACKAGER} --target /work/build/dist/${PLATFORM}
    then
        echo "Failed to create ${PACKAGER} package"
    fi
done
