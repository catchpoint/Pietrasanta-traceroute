#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
usage()
{
    echo -e "\nUsage: $0 [--clean] [--build] [--platform=<platforms>] [--arch=<architecture>]"
    echo -e "--clean: Clean the docker images and containers used during the build process for the provided platforms."
    echo -e "--build: Build traceroute binaries for the provided platforms."
    echo -e "--platform: A space-separated list containing ol8, ol9, debian12 or ubuntu24. (default: \"ol8 ol9 debian12 ubuntu24\")"
    echo -e "--arch: A space-separated list containing x86_64 or arm64. (default: \"x86_64 arm64\")"
    echo -e "\n"
    echo -e "Example: $0 --build --clean --platform=\"ol8\" --arch=\"x86_64\" # builds only for ol8 on x86_64"
    echo -e "Example: $0 --build --clean # builds everything"
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
    if ! cp -r "${SCRIPTPATH}/../libsupp" ./; then
        echo "Failed to copy libsupp"
        return 1
    fi

    if ! cp -r "${SCRIPTPATH}/../include" ./; then
        echo "Failed to copy include"
        return 1
    fi

    if ! cp -r "${SCRIPTPATH}/../traceroute" ./; then
        echo "Failed to copy traceroute"
        return 1
    fi

    if ! cp "${SCRIPTPATH}/../Makefile" ./; then
        echo "Failed to copy Makefile"
        return 1
    fi

    if ! cp "${SCRIPTPATH}/../default.rules" ./; then
        echo "Failed to copy default.rules"
        return 1
    fi

    if ! cp "${SCRIPTPATH}/../VERSION" ./; then
        echo "Failed to copy VERSION"
        return 1
    fi

    if ! cp "${SCRIPTPATH}/compile.sh" ./; then
        echo "Failed to copy compile.sh"
        return 1
    fi
}

platform_info()
{
    local PLATFORM=$1
    local ARCH=$2

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
    local PLATFORM=$1
    local ARCH=$2
    platform_info "${PLATFORM}" "${ARCH}" || return 1
    
    if docker container ls --filter "name=traceroute_${PLATFORM_IMAGE}_container"; then
        if ! docker container rm -f "traceroute_${PLATFORM_IMAGE}_container"; then
            echo "Failed to remove container traceroute_${PLATFORM_IMAGE}_container"
            return 1
        fi
    fi

    if docker image ls --filter "reference=traceroute:${PLATFORM_IMAGE}"; then
        if ! docker image rm traceroute:"${PLATFORM_IMAGE}"; then
            echo "Failed to remove image traceroute:${PLATFORM_IMAGE}"
            return 1
        fi
    fi
}

build_docker()
{
    local PLATFORM=$1
    local ARCH=$2
    platform_info "${PLATFORM}" "${ARCH}" || return 1
    
    echo "Starting docker for ${PLATFORM}/${ARCH}"
    
    if ! docker build . -t traceroute:"${PLATFORM_IMAGE}"; then
        echo "Failed to build docker for ${PLATFORM}/${ARCH}"
        return 1
    fi
    
    if docker container ls --filter "name=traceroute_${PLATFORM_IMAGE}_container"; then
        if ! docker container rm -f "traceroute_${PLATFORM_IMAGE}_container"; then
            echo "Failed to remove container traceroute_${PLATFORM_IMAGE}_container"
            return 1
        fi
    fi
    
    if ! docker create --name "traceroute_${PLATFORM_IMAGE}_container" traceroute:"${PLATFORM_IMAGE}"; then
        echo "Failed to create container traceroute_${PLATFORM_IMAGE}_container"
        return 1
    fi
 
    if ! mkdir -p "${SCRIPTPATH}/../binaries/${PLATFORM_OUTPUT}/"; then
        echo "Cannot create directory to store binary"
        return 1
    fi

    if ! docker cp "traceroute_${PLATFORM_IMAGE}_container":/traceroute/traceroute/traceroute "${SCRIPTPATH}/../binaries/${PLATFORM_OUTPUT}/"; then
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

    if ! cd "${SCRIPTPATH}/${PLATFORM_CONTEXT}"; then
        echo "Platform context ${PLATFORM_CONTEXT} not found" >&2
        return 1
    fi

    clean_folder

    if ! prepare_docker_context; then
        echo "Failed to prepare docker context"
        return 1
    fi
    
    if ! build_docker "${PLATFORM}" "${ARCH}" 2>&1; then
        echo "An error occurred while building for ${PLATFORM}/${ARCH}"
        return 1
    fi
    
    clean_folder
    
    if ! cd "$SAVE_DIR"; then
        echo "Cannot come back to ${SAVE_DIR}, aborting"
        return 1
    fi
}

# main

BUILD=0
CLEAN=0
PLATFORM="debian12 ol8 ol9 ubuntu24"
ARCHS="x86_64 arm64"

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
            ARCHS=$2; shift 2 ;;
        --)
            shift; break ;;
        *)
            echo "Internal error!" >&2; exit 2 ;;
    esac
done

if [ $BUILD -eq 0 ] && [ $CLEAN -eq 0 ]; then
    echo "${BUILD} ${CLEAN}"
    usage
    exit 1
fi

echo "Operations: BUILD=${BUILD}, CLEAN=${CLEAN}"
echo "PLATFORM=${PLATFORM}"
echo "ARCHS=${ARCHS}"

for PLATFORM in $(echo $PLATFORM)
do
    echo "Doing $PLATFORM"

    for ARCH in $(echo $ARCHS)
    do
        if ! platform_info "${PLATFORM}" "${ARCH}"; then
            exit 1
        fi

        if [ "${BUILD}" =  1 ]; then
            if ! build "${PLATFORM}" "${ARCH}"; then
                exit 1
            fi
        fi
        
        if [ "$CLEAN" = "1" ]; then
            if ! clean_docker "${PLATFORM}" "${ARCH}"; then
                exit 1
            fi
        fi
    done 
done

echo 

if [ "${BUILD}" =  1 ]; then
    echo "Build completed"
    echo "Traceroute binaries have been copied into ${SCRIPTPATH}/../binaries"
fi

exit 0
