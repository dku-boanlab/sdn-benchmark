#!/bin/bash

# move to the ONOS directory
cd ~/onos

# exectue ONOS
bazel run onos-local -- clean

# execute ONOS in debug mode
#bazel run onos-local -- clean debug
