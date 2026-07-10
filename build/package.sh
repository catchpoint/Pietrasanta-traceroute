#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SOURCE_DIR="${SCRIPTPATH}/.."

if [ ! -e ${SOURCE_DIR}/binaries/ol8/traceroute ]
then
    if ! ./build.sh - --build --clean --platform=ol8
    then
        echo "Failed to build for ol8"
    fi
fi

VERSION=$(awk '{print $NF}' ${SOURCE_DIR}/VERSION)

for PACKAGER in rpm deb
do
    if ! docker run --rm  \
        -v "${SOURCE_DIR}:/work" \
        -w /work \
        -e VERSION=${VERSION} \
        -e ARCH=amd64 \
        goreleaser/nfpm:v2.44.0 package --config /work/build/package.yaml --packager ${PACKAGER} --target /work/build/
    then
        echo "Failed to create ${PACKAGER} package"
    fi
done