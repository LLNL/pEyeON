#!/bin/bash

export eyeon_dir=$(pwd)
export LANGUAGE=en_US.UTF-8

# dependencies
yum update -y && yum groupinstall -y 'Development Tools' && yum install -y \
    python3.12 git make wget unzip python3.12-devel cmake file \

# run dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
#    && yum install -y file-libs

cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

cd /opt \
    && wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
    && tar zxf ssdeep-2.14.1.tar.gz \
    && cd ssdeep-2.14.1 && ./configure \
    && make && make install

yum clean all

cd $eyeon_dir
# set up virtual environment
python3.12 -m venv /eye && /eye/bin/pip install peyeon 
