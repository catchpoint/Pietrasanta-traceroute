#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SOURCE_DIR="${SCRIPTPATH}/.."

usage()
{
    echo "Usage: $0 [--platform=<platforms>] [--arch=<architectures>]"
    echo "  --platform: A space-separated list containing ol8, ol9, debian12 or ubuntu24. (default: all)"
    echo "  --arch: A space-separated list containing x86_64 or arm64. (default: all)"
    echo ""
    echo "  RPM packages are generated for ol8 and ol9."
    echo "  DEB packages are generated for debian12 and ubuntu24."
}

PLATFORM="ol8 ol9 debian12 ubuntu24"
ARCHS="x86_64 arm64"

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
            ARCHS=$2; shift 2 ;;
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

VERSION=$(awk '{print $NF}' ${SOURCE_DIR}/VERSION)

for PLATFORM in ${PLATFORM}
do
    case "${PLATFORM}" in
        ol8|ol9) PACKAGERS="rpm" ;;
        debian12|ubuntu24) PACKAGERS="deb" ;;
        *)
            echo "Unsupported package platform: ${PLATFORM}" >&2
            echo "Use ol8, ol9, debian12 or ubuntu24." >&2
            exit 1
            ;;
    esac

    for ARCH in ${ARCHS}
    do
        case "${ARCH}" in
            x86_64) PACKAGE_ARCH=amd64 ;;
            arm64) PACKAGE_ARCH=arm64 ;;
            *)
                echo "Unsupported package architecture: ${ARCH}. Use x86_64 or arm64." >&2
                exit 1
                ;;
        esac

        PLATFORM_DIR="${PLATFORM}/${ARCH}"
        if [ ! -e "${SOURCE_DIR}/binaries/${PLATFORM_DIR}/traceroute" ]; then
            if ! "${SCRIPTPATH}/build.sh" --build --clean --platform="${PLATFORM}" --arch="${ARCH}"; then
                echo "Failed to build for ${PLATFORM}/${ARCH}" >&2
                exit 1
            fi
        fi

        if ! mkdir -p "${SCRIPTPATH}/dist/${PLATFORM}"; then
            echo "Failed to create directory ${SCRIPTPATH}/dist/${PLATFORM}" >&2
            exit 1
        fi

        for PACKAGER in ${PACKAGERS}; do
            if ! docker run --rm \
                -v "${SOURCE_DIR}:/work" \
                -w /work \
                -e VERSION="${VERSION}" \
                -e ARCH="${PACKAGE_ARCH}" \
                -e PLATFORM="${PLATFORM}" \
                -e PLATFORM_DIR="${PLATFORM_DIR}" \
                goreleaser/nfpm:v2.44.0 package --config /work/build/package.yaml --packager "${PACKAGER}" --target "/work/build/dist/${PLATFORM}"; then
                echo "Failed to create ${PACKAGER} package for ${PLATFORM}/${ARCH}" >&2
                exit 1
            fi
        done
    done
done
