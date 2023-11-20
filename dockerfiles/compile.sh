#!/bin/sh

DISABLE_OPENSSL=$1

if [ "$DISABLE_OPENSSL" != "1" ]
then
    cd openssl
    make clean
    ./config
    make
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
