#!/bin/bash

cd openssl
make clean
./config
NPROC=$(nproc)
if [ "${NPROC}" -gt 1 ]
then
    NPROC=$((NPROC - 1))
fi
make -j "${NPROC}"
cd ..