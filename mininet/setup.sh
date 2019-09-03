#!/bin/bash

sudo apt-get install -y python-pip
pip install setuptools

CUR=$(pwd)

cd ~

# if Mininet doesn't exist, download it
if [ ! -d "mininet" ]; then
    git clone https://github.com/mininet/mininet.git
else
    echo "Mininet is already here"
    exit
fi

# install all packages in Mininet
cd ~/mininet
util/install.sh -a

# copy a POX running script and mininet scripts to HOME
cp $CUR/pox/run_pox.sh ~
cp $CUR/mn_single.sh $CUR/mn_linear.sh $CUR/mn_tree.sh ~
