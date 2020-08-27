#!/bin/bash

# Oracle java 8

sudo apt-get install -y wget
wget -P /tmp/ http://www.sdxdata.com/downloads/jdk-8u202-linux-x64.tar.gz

sudo mkdir -p /usr/lib/java
sudo tar xvfz /tmp/jdk-8u202-linux-x64.tar.gz -C /usr/lib/java/

echo "PATH=$PATH:/usr/lib/java/jdk1.8.0_202/bin" | sudo tee -a /etc/environment
echo "JAVA_HOME=/usr/lib/java/jdk1.8.0_202/" | sudo tee -a /etc/environment
echo "JRE_HOME=/usr/lib/java/jdk1.8.0_202/jre" | sudo tee -a /etc/environment

. /etc/environment
. ~/.bashrc

sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/java/jdk1.8.0_202/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/java/jdk1.8.0_202/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/java/jdk1.8.0_202/bin/javaws" 1

# ONOS

cp run_onos.sh ~

mkdir ~/Downloads ~/Applications

cd ~/Downloads

wget http://archive.apache.org/dist/karaf/3.0.5/apache-karaf-3.0.5.tar.gz
wget http://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz
tar -zxvf apache-karaf-3.0.5.tar.gz -C ~/Applications/
tar -zxvf apache-maven-3.3.9-bin.tar.gz -C ~/Applications/

sudo apt-get update
sudo apt-get install git zip unzip python -y

cd ~

git clone -b onos-1.14 https://github.com/opennetworkinglab/onos
echo ". ~/onos/tools/dev/bash_profile" >> ~/.bashrc
. ~/.bashrc

cd ~/onos
tools/build/onos-buck build onos --show-output

#tools/test/bin/onos localhost
#mvn clean install
