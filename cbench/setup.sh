#!/bin/bash

sudo apt-get install -y libsnmp-dev libpcap-dev libconfig-dev

rm -rf ~/openflow
cp -r openflow ~

if [ -z $1 ]; then
	echo "$0 [ orig | real ]"
	exit
elif [ "$1" == "orig" ]; then
	rm -rf ~/oflops
	cp -r oflops ~
elif [ "$1" == "real" ]; then
	rm -rf ~/oflops
	cp -r oflops-real ~/oflops
fi

cd ~/oflops

./boot.sh
./configure --with-openflow-src-dir=~/openflow
make
sudo make install
