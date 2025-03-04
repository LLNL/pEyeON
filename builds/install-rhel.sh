export eyeon_dir=$(pwd)
export LANGUAGE=en_US.UTF-8

# dependencies
yum update -y && yum groupinstall -y 'Development Tools' && yum install -y \
    python3.12 git make wget unzip python3.12-devel cmake file

cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

cd /opt \
    && wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
    && tar zxf ssdeep-2.14.1.tar.gz \
    && cd ssdeep-2.14.1 && ./configure \
    && make && make install

yum clean all

# set up virtual environment
cd $eyeon_dir
python3.12 -m venv eye \
    && /eye/bin/pip install --upgrade pip \
    && /eye/bin/pip install peyeon

#add eyeon to paths
echo 'export PATH="/eye/bin:$PATH"' >> /root/.bashrc
echo 'export PATH="/root/.local/bin:$PATH"' >> /root/.bashrc
