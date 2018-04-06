#!/bin/bash

# install dependencies
sudo apt-get -y install default-jre default-jdk

# if Beacon exists, remove it
rm -rf ~/beacon ~/run_beacon.sh

# decompress Beacon to HOME
tar -zxvf beacon/beacon-1.0.4-linux_x86_64.tar.gz -C ~
cp beacon/run_beacon.sh ~

# set up the running cores, which is equal to available cores in your system, in the configuration file
mv ~/beacon-1.0.4 ~/beacon
sed -i 's/#controller.threadCount=1/controller.threadCount='$(nproc)'/g' ~/beacon/beacon.properties
