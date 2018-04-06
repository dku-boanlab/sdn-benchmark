#!/bin/bash

# if SE-Floodlight exists, remove the old one
rm -rf ~/se-floodlight ~/run_sfl.sh ~/sfl_setup.sh

# copy a new one to HOME
cp -r se-floodlight ~

# move a running script to HOME
mv ~/se-floodlight/run_sfl.sh ~
