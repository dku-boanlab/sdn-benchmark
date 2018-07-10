#!/bin/bash

# move to the ONOS directory
cd ~/onos

# exectue ONOS as a single mode
tools/build/onos-buck run onos-local -- clean debug
