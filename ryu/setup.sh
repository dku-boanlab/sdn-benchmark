#!/bin/bash

CURR=`pwd`

# first install dependencies
sudo apt-get -y install gcc python-dev python-pip libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev

cd ~

# then install ryu
git clone https://github.com/faucetsdn/ryu.git
cd ryu; git checkout -b v4.34
pip install .
pip install -r tools/optional-requires

cd $CURR

# copy the running script to HOME
cp ryu/run_ryu.sh ~
