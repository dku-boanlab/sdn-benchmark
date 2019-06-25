#!/bin/bash

# if NOX exists, remove the old one
rm -rf ~/nox ~/run_nox.sh

# copy a new one and the running script to HOME
mkdir ~/nox
cp -r nox/boost-1.46.1 ~/nox
cp -r nox/nox ~/nox
cp nox/run_nox.sh ~

# install dependencies
sudo apt-get -y install gcc-4.6 g++-4.6 autoconf
sudo apt-get -y install build-essential python-dev libtbb-dev libssl-dev libtool twisted* libbz2-dev libicu-dev

# temporarily change the gcc version
sudo mv /usr/bin/gcc /usr/bin/gcc.bak
sudo mv /usr/bin/g++ /usr/bin/g++.bak
sudo ln -s /usr/bin/gcc-4.6 /usr/bin/gcc
sudo ln -s /usr/bin/g++-4.6 /usr/bin/g++

# install boost
cd ~/nox/boost-1.46.1/boost_1_46_1
./bootstrap.sh --exec-prefix=/usr/local
./bjam
sudo ./bjam install
sudo ldconfig

# install NOX
cd ~/nox/nox
./boot.sh
mkdir build; cd build
../configure
make

# recover the previous gcc version
sudo mv /usr/bin/gcc.bak /usr/bin/gcc
sudo mv /usr/bin/g++.bak /usr/bin/g++
