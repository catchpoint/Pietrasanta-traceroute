#!/bin/bash
set -x

build()
{
    PLATFORM=$1
    OPENSSL3_FOLDER=$2
    
    if [ ! -e "$OPENSSL3_FOLDER" ]
    then
        echo "openssl3 folder ${OPENSSL3_FOLDER} does not exist."
        exit 1
    fi

    echo "Building for $PLATFORM"
    
    SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
    SAVE_DIR="${SCRIPTPATH}"
    
    if ! cd "${SCRIPTPATH}/${PLATFORM}"
    then
        echo "Platform $PLATFORM not found, skipping it"
        continue
    fi

    clean_folder
    prepare_docker_context ${OPENSSL3_FOLDER}
    
    if ! build_docker "$PLATFORM" $DISABLE_OPENSSL 2>&1
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

build_docker()
{
    PLATFORM=$1
    DISABLE_OPENSSL=$2
    
    echo "Starting docker for ${PLATFORM}, DISABLE_OPENSSL=${DISABLE_OPENSSL}"
    
    if ! docker build -f Dockerfile_openssl . -t traceroute_openssl:"${PLATFORM}"
    then
        echo "Failed to build docker for platform ${PLATFORM}"
        return 1
    fi
    
    docker create --name "traceroute_openssl_${PLATFORM}_container" traceroute_openssl:"${PLATFORM}"
 
    if ! mkdir -p  ./precompiled_openssl
    then
        echo "Cannot create directory to store openssl libraries"
        exit 1
    fi

    if ! docker cp "traceroute_openssl_${PLATFORM}_container":/openssl/libcrypto.so.3 ./precompiled_openssl/libcrypto.so.3
    then
        echo "Failed to copy libcrypto.so.3 artifact from container traceroute_openssl_${PLATFORM}_container"
        return 1
    fi
    
    if ! docker cp "traceroute_openssl_${PLATFORM}_container":/openssl/libssl.so.3 ./precompiled_openssl/libssl.so.3
    then
        echo "Failed to copy libssl.so.3 artifact from container traceroute_openssl_${PLATFORM}_container"
        return 1
    fi

    if ! docker cp "traceroute_openssl_${PLATFORM}_container":/openssl/include/ ./precompiled_openssl/include
    then
        echo "Failed to copy include files from container traceroute_openssl_${PLATFORM}_container"
        return 1
    fi
    
    return 0
}

clean_docker()
{
    PLATFORM=$1
    docker container rm -f "traceroute_openssl_${PLATFORM}_container"
    docker image rm traceroute_openssl:"${PLATFORM}"
}

prepare_docker_context()
{
    OPENSSL3_FOLDER=$1
    cp ../compile_openssl.sh ./
    cp -r ${OPENSSL3_FOLDER} ./openssl
}

clean_folder()
{
    rm -rf openssl/
    rm compile_openssl.sh
}

## main

OPENSSL3_FOLDER=""
PLATFORMS="ol8 ol9 debian12 ubuntu24"

if ! args=$(getopt --long openssl3:,platform: -n 'invalid arguments' -- "$@"); then
    exit 2
fi

eval set -- "$args"

while true; do
    case "$1" in
        --platform)
            PLATFORMS=$2; shift 2 ;;
        --openssl3)
            OPENSSL3_FOLDER=$2; shift 2 ;;
        --)
            shift; break ;;
        *)
            echo "Internal error!" >&2; exit 2 ;;
    esac
done

for PLATFORM in $(echo $PLATFORMS)
do
    echo "Doing $PLATFORM"
    
    build ${PLATFORM} ${OPENSSL3_FOLDER}
    clean_docker ${PLATFORM}
done