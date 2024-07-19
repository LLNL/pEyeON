FROM ubuntu:22.04
USER root

RUN apt update 

# Install LLNL CSP certs
RUN apt-get install -y ca-certificates
ADD https://www-csp.llnl.gov/content/assets/csoc/cspca.crt /usr/local/share/ca-certificates/cspca.crt
RUN chmod 644 /usr/local/share/ca-certificates/cspca.crt && update-ca-certificates

RUN apt install -y python3 python3-pip python3-dev python3-venv libmagic1 git make wget unzip build-essential vim ssdeep jq \
    && pip3 install build sphinx pre-commit black

RUN wget https://github.com/Kitware/CMake/releases/download/v3.27.4/cmake-3.27.4-linux-x86_64.sh \
    && chmod u+x cmake-3.27.4-linux-x86_64.sh \
    && mkdir /opt/cmake-3.27.4 \
    && ./cmake-3.27.4-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.27.4 \
    && rm cmake-3.27.4-linux-x86_64.sh \
    && ln -s /opt/cmake-3.27.4/bin/* /usr/local/bin

COPY . /workdir
RUN ls /workdir

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

RUN pip3 install telfhash

RUN cd /workdir && python3 -m build && pip uninstall -y eyeon && pip install /workdir/dist/eyeon*.whl
