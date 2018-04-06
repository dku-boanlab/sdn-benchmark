#!/bin/bash

# set the IP address
IP=127.0.0.1

# create a linear topology
if [ -z $1 ]; then
sudo mn --controller=remote,ip=$IP,port=6633 --topo linear,2
else
sudo mn --controller=remote,ip=$IP,port=6633 --topo linear,$1
fi
