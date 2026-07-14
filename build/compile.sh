#!/bin/sh

# This script is run inside the docker container to compile the traceroute binary. It is called by the build.sh script.

cd traceroute
make clean
make traceroute
