#!/bin/bash

rm -rf ~/oflops ~/openflow

cp -r oflops openflow ~

cd ~/oflops

./boot.sh
./configure
make
sudo make install
