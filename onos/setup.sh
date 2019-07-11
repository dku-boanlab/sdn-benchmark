#!/bin/bash

# Oracle java 8

sudo apt-get install -y wget
wget -P /tmp/ http://www.sdx4u.net/downloads/jdk-8u202-linux-x64.tar.gz

sudo mkdir -p /usr/lib/jvm
sudo tar xvfz /tmp/jdk-8u202-linux-x64.tar.gz -C /usr/lib/jvm/

echo "PATH=$PATH:/usr/lib/jvm/jdk1.8.0_202/bin" | sudo tee -a /etc/environment
echo "JAVA_HOME=/usr/lib/jvm/jdk1.8.0_202/" | sudo tee -a /etc/environment
echo "CLASSPATH=JAVA_HOME=/usr/lib/jvm/jdk1.8.0_202/lib" | sudo tee -a /etc/environment

. /etc/environment

sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_202/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_202/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_202/bin/javaws" 1

# ONOS

cp run_onos.sh ~

mkdir ~/Downloads ~/Applications

cd ~/Downloads

wget http://archive.apache.org/dist/karaf/3.0.5/apache-karaf-3.0.5.tar.gz
wget http://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz
tar -zxvf apache-karaf-3.0.5.tar.gz -C ~/Applications/
tar -zxvf apache-maven-3.3.9-bin.tar.gz -C ~/Applications/

sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:webupd8team/java -y

sudo apt-get update
sudo apt-get install git zip unzip -y
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | sudo debconf-set-selections && \
sudo apt-get install oracle-java8-installer oracle-java8-set-default -y

cd ~

git clone -b onos-1.14 https://github.com/opennetworkinglab/onos
echo ". ~/onos/tools/dev/bash_profile" >> ~/.bashrc
. ~/.bashrc

cd ~/onos
tools/build/onos-buck build onos --show-output

#tools/test/bin/onos localhost
#mvn clean install
