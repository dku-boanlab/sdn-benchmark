#!/bin/bash

mkdir ~/Downloads ~/Applications
cd ~/Downloads
wget http://archive.apache.org/dist/karaf/3.0.5/apache-karaf-3.0.5.tar.gz
wget http://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz
tar -zxvf apache-karaf-3.0.5.tar.gz -C ~/Applications/
tar -zxvf apache-maven-3.3.9-bin.tar.gz -C ~/Applications/

sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:webupd8team/java -y
sudo apt-get update
sudo apt-get install oracle-java8-installer oracle-java8-set-default -y

cd ~
sudo apt-get install git zip unzip -y
git clone -b onos-1.9 https://github.com/opennetworkinglab/onos
. ~/onos/tools/dev/bash_profile
echo ". ~/onos/tools/dev/bash_profile" >> ~/.bashrc
cd ~/onos
mvn clean install
