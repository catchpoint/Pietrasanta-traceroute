#!/bin/sh

DISABLE_OPENSSL=$1

if [ "$DISABLE_OPENSSL" != "1" ]
then
    cd openssl
    make clean
    ./config
    NPROC=$(nproc)
    if [ ${NPROC} -gt 1 ]
    then
        NPROC=$((NPROC - 1))
    fi
    make -j ${NPROC}
    make install
    cd ..
fi

cd traceroute
make clean

if [ "$DISABLE_OPENSSL" = "1" ]
then
    make DISABLE_OPENSSL=1
else
    make
fi
