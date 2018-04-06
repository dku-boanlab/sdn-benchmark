#!/bin/bash

# first install dependencies
sudo apt-get -y install python-dev python-pip
sudo pip install setuptools
sudo pip install -U netaddr six pbr rfc3986 stevedore debtcollector oslo.i18n greenlet

# then install ryu using pip
sudo pip install ryu

# copy the running script to HOME
cp ryu/run_ryu.sh ~
