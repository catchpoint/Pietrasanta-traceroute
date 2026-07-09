#!/bin/bash
set -x
usage()
{
    echo -e "\nUsage: $0 - [--clean] [--build] [--platform=<platforms>"
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
    
    echo "Starting docker for ${PLATFORM}"
    
    if ! docker build . -t traceroute:"${PLATFORM}"
    then
        echo "Failed to build docker for platform ${PLATFORM}"
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
    
    echo "Building for $PLATFORM"
    
    SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
    SAVE_DIR="${SCRIPTPATH}"
    
    if ! cd "${SCRIPTPATH}/${PLATFORM}"
    then
        echo "Platform $PLATFORM not found, skipping it"
        continue
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
PLATFORM="debian12 ol8 ol9 ubuntu24"

if ! args=$(getopt --long build,clean,help,platform: -n 'invalid arguments' -- "$@"); then
    exit 2
fi

eval set -- "$args"

while true; do
    case "$1" in
        --build)
            echo "ejejjeje"
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

