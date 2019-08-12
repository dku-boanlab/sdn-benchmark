#!/bin/bash

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
./configure
make
sudo make install
