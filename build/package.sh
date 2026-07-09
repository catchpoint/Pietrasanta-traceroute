#!/bin/bash
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"; echo ${SCRIPTPATH}
SOURCE_DIR="${SCRIPTPATH}/.."

if [ ! -e SOURCE_DIR/binaries/ol8/traceroute ]
then
    if ! ./build.sh - --build --clean --platform=ol8
    then
        echo "Failed to build for ${PLATFORM}"
    fi
fi

CONF="amd64.yaml"
ACTUAL_CONF="conf.yaml"

VERSION=$(awk '{print $NF}' ${SOURCE_DIR}/VERSION)
sed "s/\${VERSION}/${VERSION}/g" ${SOURCE_DIR}/build/${CONF} > ${SOURCE_DIR}/build/${ACTUAL_CONF}

for PACKAGER in rpm deb
do
    docker run --rm   -v "${SOURCE_DIR}:/work" -w /work goreleaser/nfpm:v2.44.0 package --config /work/build/${ACTUAL_CONF} --packager ${PACKAGER} --target /work/build/
done