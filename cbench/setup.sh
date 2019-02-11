#!/bin/bash

rm -rf ~/openflow
cp -r openflow ~

if [ -z $1 ]; then
	rm -rf ~/oflops
	cp -r oflops ~
else
	rm -rf ~/oflops
	cp -r oflops-real ~/oflops
fi

cd ~/oflops

./boot.sh
./configure
make
sudo make install
