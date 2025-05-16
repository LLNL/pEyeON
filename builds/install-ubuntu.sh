#!/bin/bash

export eyeon_dir=$(pwd)
# dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt-get install -y python3 python3-pip python3-dev python3-venv \
    libmagic1 git make wget unzip build-essential vim ssdeep jq

# cmake, have to build telfhash
wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3-linux-x86_64.sh
chmod u+x cmake-3.30.3-linux-x86_64.sh
mkdir /opt/cmake-3.30.3
./cmake-3.30.3-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.30.3
rm cmake-3.30.3-linux-x86_64.sh
ln -s /opt/cmake-3.30.3/bin/* /usr/local/bin

# build/install telfhash C++ backend and python frontend
cd /opt && git clone https://github.com/trendmicro/tlsh.git
cd /opt/tlsh
./make.sh

cd $eyeon_dir
# set up virtual environment
python3 -m venv eye && source eye/bin/activate
pip install peyeon
