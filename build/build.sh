#!/bin/bash
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
usage()
{
    echo -e "\nUsage: $0 [--clean] [--build] [--platform=<platforms>]"
    echo -e "--clean: Clean the docker images and containers used during the build process for the provided platforms."
    echo -e "--build: Build traceroute binaries for the provided platforms."
    echo -e "--platform: The platform taken in consideration when building and cleaning. Can be a space separated string containing either of the following:"
    echo -e "\tol8-x86_64: Oracle Linux 8 x86_64 (alias: ol8)"
    echo -e "\tol8-arm64: Oracle Linux 8 ARM64 (alias: ol8-aarch64)"
    echo -e "\tol9-x86_64: Oracle Linux 9 x86_64 (alias: ol9)"
    echo -e "\tol9-arm64: Oracle Linux 9 ARM64 (alias: ol9-aarch64)"
    echo -e "\tdebian12-x86_64: Debian 12 x86_64 (alias: debian12)"
    echo -e "\tdebian12-arm64: Debian 12 ARM64 (alias: debian12-aarch64)"
    echo -e "\tubuntu24-x86_64: Ubuntu 24.04 x86_64 (alias: ubuntu24)"
    echo -e "\tubuntu24-arm64: Ubuntu 24.04 ARM64 (alias: ubuntu24-aarch64)"
    echo -e "\tBy default all are enabled"
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
    case "$1" in
        ol8|ol8-x86_64)
            PLATFORM_CONTEXT="ol8/x86_64"
            PLATFORM_OUTPUT="ol8/x86_64"
            PLATFORM_IMAGE="ol8-x86_64"
            ;;
        ol8-aarch64|ol8-arm64)
            PLATFORM_CONTEXT="ol8/arm64"
            PLATFORM_OUTPUT="ol8/arm64"
            PLATFORM_IMAGE="ol8-arm64"
            ;;
        ol9|ol9-x86_64)
            PLATFORM_CONTEXT="ol9/x86_64"
            PLATFORM_OUTPUT="ol9/x86_64"
            PLATFORM_IMAGE="ol9-x86_64"
            ;;
        ol9-aarch64|ol9-arm64)
            PLATFORM_CONTEXT="ol9/arm64"
            PLATFORM_OUTPUT="ol9/arm64"
            PLATFORM_IMAGE="ol9-arm64"
            ;;
        debian12|debian12-x86_64)
            PLATFORM_CONTEXT="debian12/x86_64"
            PLATFORM_OUTPUT="debian12/x86_64"
            PLATFORM_IMAGE="debian12-x86_64"
            ;;
        debian12-aarch64|debian12-arm64)
            PLATFORM_CONTEXT="debian12/arm64"
            PLATFORM_OUTPUT="debian12/arm64"
            PLATFORM_IMAGE="debian12-arm64"
            ;;
        ubuntu24|ubuntu24-x86_64)
            PLATFORM_CONTEXT="ubuntu24/x86_64"
            PLATFORM_OUTPUT="ubuntu24/x86_64"
            PLATFORM_IMAGE="ubuntu24-x86_64"
            ;;
        ubuntu24-aarch64|ubuntu24-arm64)
            PLATFORM_CONTEXT="ubuntu24/arm64"
            PLATFORM_OUTPUT="ubuntu24/arm64"
            PLATFORM_IMAGE="ubuntu24-arm64"
            ;;
        *)
            echo "Unsupported platform: $1" >&2
            return 1
            ;;
    esac
}

clean_docker()
{
    PLATFORM=$1
    platform_info "${PLATFORM}" || return 1
    docker container rm -f "traceroute_${PLATFORM_IMAGE}_container"
    docker image rm traceroute:"${PLATFORM_IMAGE}"
}

build_docker()
{
    PLATFORM=$1
    platform_info "${PLATFORM}" || return 1
    
    echo "Starting docker for ${PLATFORM}"
    
    if ! docker build . -t traceroute:"${PLATFORM_IMAGE}"
    then
        echo "Failed to build docker for platform ${PLATFORM}"
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
    platform_info "${PLATFORM}" || return 1
    
    echo "Building for $PLATFORM"
    
    SAVE_DIR="${SCRIPTPATH}"

    if ! cd "${SCRIPTPATH}/${PLATFORM_CONTEXT}"
    then
        echo "Platform context ${PLATFORM_CONTEXT} not found" >&2
        return 1
    fi

    clean_folder
    prepare_docker_context
    
    if ! build_docker "$PLATFORM" 2>&1
    then
        echo "An error occurred while building for platform $PLATFORM"
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
PLATFORM="debian12-x86_64 debian12-arm64 ol8-x86_64 ol8-arm64 ol9-x86_64 ol9-arm64 ubuntu24-x86_64 ubuntu24-arm64"

if ! args=$(getopt -o '' --long build,clean,help,platform: -n 'invalid arguments' -- "$@"); then
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

for PLATFORM in $(echo $PLATFORM)
do
    echo "Doing $PLATFORM"
    
    if [ "${BUILD}" =  1 ]
    then
        build ${PLATFORM}
    fi
    
    if [ "$CLEAN" = "1" ]
    then
        clean_docker ${PLATFORM}
    fi
done

echo 

if [ "${BUILD}" =  1 ]
then
    echo "Build completed"
    echo "Traceroute binaries have been copied into ${SCRIPTPATH}/../binaries"
fi

exit 0
