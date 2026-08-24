#!/bin/bash
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
usage()
{
    echo -e "\nUsage: $0 [--clean] [--build] [--platform=<platforms>] [--arch=<architecture>]"
    echo -e "--clean: Clean the docker images and containers used during the build process for the provided platforms."
    echo -e "--build: Build traceroute binaries for the provided platforms."
    echo -e "--platform: A space-separated list containing ol8, ol9, debian12 or ubuntu24."
    echo -e "--arch: Target architecture: x86_64 or arm64 (default: x86_64)."
    echo -e "\n"
    echo -e "Example: $0 --build --clean"
    echo -e "\n"
}

clean_folder()
{
    rm -rf libsupp/
    rm -rf include/
    rm -rf traceroute/
    rm -f default.rules
    rm -f Makefile
    rm -f VERSION
    rm -rf ./openssl
    rm -f compile.sh
    rm -f placeholder_openssl
}

prepare_docker_context()
{
    cp -r "${SCRIPTPATH}/../libsupp" ./
    cp -r "${SCRIPTPATH}/../include" ./
    cp -r "${SCRIPTPATH}/../traceroute" ./
    cp "${SCRIPTPATH}/../Makefile" ./
    cp "${SCRIPTPATH}/../default.rules" ./
    cp "${SCRIPTPATH}/../VERSION" ./
    cp "${SCRIPTPATH}/compile.sh" ./
}

platform_info()
{
    PLATFORM=$1
    ARCH=$2

    case "${ARCH}" in
        x86_64|arm64)
            ;;
        *)
            echo "Unsupported architecture: ${ARCH}. Use x86_64 or arm64." >&2
            return 1
            ;;
    esac

    case "${PLATFORM}" in
        ol8|ol9|debian12|ubuntu24)
            ;;
        *)
            echo "Unsupported platform: ${PLATFORM}. Use ol8, ol9, debian12 or ubuntu24." >&2
            return 1
            ;;
    esac

    PLATFORM_CONTEXT="${PLATFORM}/${ARCH}"
    PLATFORM_OUTPUT="${PLATFORM}/${ARCH}"
    PLATFORM_IMAGE="${PLATFORM}-${ARCH}"
}

clean_docker()
{
    PLATFORM=$1
    ARCH=$2
    platform_info "${PLATFORM}" "${ARCH}" || return 1
    docker container rm -f "traceroute_${PLATFORM_IMAGE}_container"
    docker image rm traceroute:"${PLATFORM_IMAGE}"
}

build_docker()
{
    PLATFORM=$1
    ARCH=$2
    platform_info "${PLATFORM}" "${ARCH}" || return 1
    
    echo "Starting docker for ${PLATFORM}/${ARCH}"
    
    if ! docker build . -t traceroute:"${PLATFORM_IMAGE}"
    then
        echo "Failed to build docker for ${PLATFORM}/${ARCH}"
        return 1
    fi
    
    docker container rm -f "traceroute_${PLATFORM_IMAGE}_container"
    docker create --name "traceroute_${PLATFORM_IMAGE}_container" traceroute:"${PLATFORM_IMAGE}"
 
    if ! mkdir -p "${SCRIPTPATH}/../binaries/${PLATFORM_OUTPUT}/"
    then
        echo "Cannot create directory to store binary"
        exit 1
    fi

    if ! docker cp "traceroute_${PLATFORM_IMAGE}_container":/traceroute/traceroute/traceroute \
        "${SCRIPTPATH}/../binaries/${PLATFORM_OUTPUT}/"
    then
        echo "Failed to copy traceroute artifact from container traceroute_${PLATFORM_IMAGE}_container"
        return 1
    fi
    
    return 0
}

build()
{
    PLATFORM=$1
    ARCH=$2
    platform_info "${PLATFORM}" "${ARCH}" || return 1
    
    echo "Building for ${PLATFORM}/${ARCH}"
    
    SAVE_DIR="${SCRIPTPATH}"

    if ! cd "${SCRIPTPATH}/${PLATFORM_CONTEXT}"
    then
        echo "Platform context ${PLATFORM_CONTEXT} not found" >&2
        return 1
    fi

    clean_folder
    prepare_docker_context
    
    if ! build_docker "${PLATFORM}" "${ARCH}" 2>&1
    then
        echo "An error occurred while building for ${PLATFORM}/${ARCH}"
        exit 1
    fi
    
    clean_folder
    
    if ! cd "$SAVE_DIR"
    then
        echo "Cannot come back to ${SAVE_DIR}, aborting"
        exit 1
    fi
}

# main

BUILD=0
CLEAN=0
PLATFORM="debian12 ol8 ol9 ubuntu24"
ARCH=x86_64

if ! args=$(getopt -o '' --long build,clean,help,platform:,arch: -n 'invalid arguments' -- "$@"); then
    exit 2
fi

eval set -- "$args"

while true; do
    case "$1" in
        --build)
            BUILD=1; shift ;;
        --clean)
            CLEAN=1; shift ;;
        --help)
            usage
            exit 0 ;;
        --platform)
            PLATFORM=$2; shift 2 ;;
        --arch)
            ARCH=$2; shift 2 ;;
        --)
            shift; break ;;
        *)
            echo "Internal error!" >&2; exit 2 ;;
    esac
done

if [ $BUILD -eq 0 ] && [ $CLEAN -eq 0 ]
then
    echo "${BUILD} ${CLEAN}"
    usage
    exit 1
fi

echo "Operations: BUILD=${BUILD}, CLEAN=${CLEAN}"
echo "PLATFORM=${PLATFORM}"
echo "ARCH=${ARCH}"

for PLATFORM in $(echo $PLATFORM)
do
    echo "Doing $PLATFORM"

    if ! platform_info "${PLATFORM}" "${ARCH}"
    then
        exit 2
    fi
    
    if [ "${BUILD}" =  1 ]
    then
        build "${PLATFORM}" "${ARCH}"
    fi
    
    if [ "$CLEAN" = "1" ]
    then
        clean_docker "${PLATFORM}" "${ARCH}"
    fi
done

echo 

if [ "${BUILD}" =  1 ]
then
    echo "Build completed"
    echo "Traceroute binaries have been copied into ${SCRIPTPATH}/../binaries"
fi

exit 0
