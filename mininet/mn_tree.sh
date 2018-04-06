#!/bin/bash

# set the IP address
IP=127.0.0.1

# create a tree topology
if [ -z $1 ]; then
sudo mn --controller=remote,ip=$IP,port=6633 --topo tree,depth=2,fanout=2
elif [ -z $2 ]; then
sudo mn --controller=remote,ip=$IP,port=6633 --topo tree,depth=$1,fanout=2
else
sudo mn --controller=remote,ip=$IP,port=6633 --topo tree,depth=$1,fanout=$2
fi
