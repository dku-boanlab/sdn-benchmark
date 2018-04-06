#!/bin/bash

# set the IP address
IP=127.0.0.1

# create a simple topology
sudo mn --controller=remote,ip=$IP,port=6633
