#!/bin/bash

CURR=`pwd`

# first install dependencies
sudo apt-get -y install python-dev python-pip

cd ~

# then install ryu
git clone -b v4.34 https://github.com/faucetsdn/ryu.git
cd ryu; pip install .

cd $CURR

# copy the running script to HOME
cp ryu/run_ryu.sh ~
