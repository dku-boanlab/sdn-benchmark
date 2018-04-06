#!/bin/bash

# move to the NOX running directory
cd ~/nox/nox/build/src

# run NOX with the specific number of cores
if [ -z $1 ]; then
    ./nox_core -i ptcp:6633 -v switch -t $(nproc)
else
    ./nox_core -i ptcp:6633 -v switch -t $1
fi
