#!/bin/bash
set -x
usage()
{
    echo -e "\nUsage: $0 - [--clean] [--build] [--platform=<platforms> [--disable-openssl3]"
    echo -e "\n--disable-openssl3: Do not use openssl3 when building the traceroute binaries. This will disable QUIC support."
    echo -e "--clean: Clean the docker images and containers used during the build process for the provided platforms."
    echo -e "--build: Build traceroute binaries for the provided platforms."
    echo -e "--platform: The platform taken in consideration when building and cleaning. Can be a space separated string containing either of the following:"
    echo -e "\tol8: Oracle Linux 8"
    echo -e "\tol9: Oracle Linux 9"
    echo -e "\tdebian12: Debian 12"
    echo -e "\tubuntu24: Ubuntu 24.04"
    echo -e "\tBy default all are enabled"
    echo -e "\n"
    echo -e "Example: $0 - --build --clean"
    echo -e "\n"
}

clean_folder()
{
    rm -rf libsupp/
    rm -rf include/
    rm -rf traceroute/
    rm -f default.rules
    rm -f Makefile
    rm -f Make.rules
    rm -f Make.defines
    rm -f VERSION
    rm -rf ./openssl
    rm -f compile.sh
    rm -f placeholder_openssl
}

prepare_docker_context()
{
    cp -r ../../libsupp ./
    cp -r ../../include ./
    cp -r ../../traceroute ./
    cp ../../Makefile ./
    cp ../../Make.rules ./
    cp ../../Make.defines ./
    cp ../../default.rules ./
    cp ../../VERSION ./
    cp ../compile.sh ./
    touch placeholder_openssl # This will be useful when trying to COPY openssl folder from the Dockerfile
}

clean_docker()
{
    PLATFORM=$1
    docker container rm -f "traceroute_${PLATFORM}_container"
    docker image rm traceroute:"${PLATFORM}"
}

build_docker()
{
    PLATFORM=$1
    DISABLE_OPENSSL=$2
    
    echo "Starting docker for ${PLATFORM}, DISABLE_OPENSSL=${DISABLE_OPENSSL}"
    
    if ! docker build . -t traceroute:"${PLATFORM}" --build-arg disable_openssl=${DISABLE_OPENSSL}
    then
        echo "Failed to build docker for platform ${PLATFORM}"
        return 1
    fi
    
    docker create --name "traceroute_${PLATFORM}_container" traceroute:"${PLATFORM}"
 
    if ! mkdir -p  ../../binaries/"$PLATFORM"/
    then
        echo "Cannot create directory to store binary"
        exit 1
    fi

    if ! docker cp "traceroute_${PLATFORM}_container":/traceroute/traceroute/traceroute ../../binaries/"$PLATFORM"/
    then
        echo "Failed to copy traceroute artifact from container traceroute_${PLATFORM}_container"
        return 1
    fi
    
    return 0
}

build()
{
    PLATFORM=$1
    DISABLE_OPENSSL=$2

    if [ "$DISABLE_OPENSSL" = "0" ]
    then
        if [ ! -e "${PLATFORM}/precompiled_openssl" ]
        then
            echo "precompiled_openssl folder does not exist for ${PLATFORM} but openssl is not disabled."
            exit 1
        fi
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

# main

BUILD=0
CLEAN=0
DISABLE_OPENSSL="0"
PLATFORM="ol8 centos7 debian11 ubuntu22 alpine3.15"

if ! args=$(getopt --long disable-openssl3,build,clean,help,platform: -n 'invalid arguments' -- "$@"); then
    exit 2
fi

eval set -- "$args"

while true; do
    case "$1" in
        --build)
            echo "ejejjeje"
            BUILD=1; shift ;;
        --disable-openssl3)
            DISABLE_OPENSSL=1; shift ;;
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
echo "DISABLE_OPENSSL=${DISABLE_OPENSSL}"
echo "PLATFORM=${PLATFORM}"

for PLATFORM in $(echo $PLATFORM)
do
    echo "Doing $PLATFORM"
    
    if [ "${BUILD}" =  1 ]
    then
        build ${PLATFORM} ${DISABLE_OPENSSL}
    fi
    
    if [ "$CLEAN" = "1" ]
    then
        clean_docker ${PLATFORM}
    fi
done

echo 

if [ "${BUILD}" =  1 ]
then
    if [ "$DISABLE_OPENSSL" = "1" ]
    then
        echo "Warning: openssl3 disabled, QUIC will not be available"
    fi

    echo "Build completed"
    echo "Traceroute binaries have been copied into ${SCRIPTPATH}/../binaries"
fi

exit 0

