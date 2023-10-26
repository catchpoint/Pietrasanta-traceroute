#!/bin/bash

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
}

copy_files()
{
    cp -r ../../libsupp ./
    cp -r ../../include ./
    cp -r ../../traceroute ./
    cp ../../Makefile ./
    cp ../../Make.rules ./
    cp ../../Make.defines ./
    cp ../../default.rules ./
    cp ../../VERSION ./
}

build()
{
    echo "Starting docker for $1"
    if ! docker build . -t traceroute:"$1"
    then
        echo "Failed to build docker for platform $1"
        return 1
    fi
    
    CONTAINER_ID=$(docker run -d traceroute:"$1")

    MAX_TIMEOUT_SEC=30
    TIMEOUT=$MAX_TIMEOUT_SEC
    while true
    do
        sleep 1
        if [ "$( docker container inspect -f '{{.State.Status}}' ${CONTAINER_ID} )" = "running" ]
        then
            break;
        fi
        TIMEOUT=$((TIMEOUT-1))
        
        if [ $TIMEOUT -eq 0 ]
        then
            echo "${CONTAINER_ID} did not start in ${MAX_TIMEOUT_SEC} sec, giving up"
            return 1
        fi
    done
    
    if ! docker exec -it "$CONTAINER_ID" /bin/bash -c "cd traceroute && make clean && make traceroute"
    then
        echo "Failed to execute docker container ${CONTAINER_ID} for platform $1"
        return 1
    fi
    
    if ! docker cp "$CONTAINER_ID":/traceroute/traceroute/traceroute ../../binaries/"$1"/
    then
        echo "Failed to copy traceroute artifact from container ${CONTAINER_ID} for platform $1"
        return 1
    fi
    
    if ! docker container stop "$CONTAINER_ID"
    then
        echo "Failed to stop container ${CONTAINER_ID} for platform $1"
        return 1
    fi
    
    if ! docker container rm "$CONTAINER_ID"
    then
        echo "Failed to remove container ${CONTAINER_ID} for platform $1"
        return 1
    fi
    
    if ! docker image rm traceroute:"$1"
    then
        echo "Failed to remove image traceroute:$1"
        return 1
    fi
    
    return 0
}

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

for PLATFORM in $(echo "centos7 debian11 ubuntu22")
do
    echo "Building for $PLATFORM"
    SAVE_DIR="${SCRIPTPATH}/${PLATFORM}"
    
    if ! cd "${SCRIPTPATH}/${PLATFORM}"
    then
        echo "Platform $PLATFORM not found, skipping it"
        continue
    fi

    rm -f "${SCRIPTPATH}/build.log"
    
    clean_folder
    copy_files
    
    if ! build "$PLATFORM" >> "${SCRIPTPATH}/build.log" 2>&1
    then
        echo "An error occurred while building for platform $PLATFORM, see ${SCRIPTPATH}/build.log for more information"
        exit 1
    fi
    
    clean_folder
    
    if ! cd "$SAVE_DIR"
    then
        echo "Cannot come back to ${SAVE_DIR}, aborting"
        exit 1
    fi
done

echo "Build completed, see ${SCRIPTPATH}/build.log for more information"
echo "Traceroute binaries have been copied into ${SCRIPTPATH}/../binaries"

exit 0


