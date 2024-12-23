FROM amd64/ubuntu:22.04

ARG USER_ID
ARG OUN

RUN apt-get update \
    && apt-get install -y python3 python3-pip python3-dev python3-venv libmagic1 git make wget unzip build-essential vim ssdeep jq \
    && groupadd -g $USER_ID $OUN \
    && useradd -ms /bin/bash $OUN -u $USER_ID -g $USER_ID \
    && pip3 install build sphinx pre-commit black


RUN echo "alias build='python3 -m build'" >> /home/$OUN/.bashrc \
    && echo "alias clean='rm -rf /workdir/dist'" >> /home/$OUN/.bashrc \
    && echo "alias rein='build && pip uninstall -y eyeon && pip install /workdir/dist/eyeon*.whl'" >> /home/$OUN/.bashrc 

RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3-linux-x86_64.sh \
    && chmod u+x cmake-3.30.3-linux-x86_64.sh \
    && mkdir /opt/cmake-3.30.3 \
    && ./cmake-3.30.3-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.30.3 \
    && rm cmake-3.30.3-linux-x86_64.sh \
    && ln -s /opt/cmake-3.30.3/bin/* /usr/local/bin

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

RUN pip3 install telfhash

RUN apt-get update && \
    apt-get install -y curl && \
    mkdir -p /opt/die && \
    apt-get clean

RUN curl -L -o /opt/die/die_3.09_Ubuntu_22.04_amd64.deb \
    https://github.com/horsicq/DIE-engine/releases/download/3.09/die_3.09_Ubuntu_22.04_amd64.deb && \
    apt-get install -y /opt/die/die_3.09_Ubuntu_22.04_amd64.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $OUN

ENV PATH=/home/$OUN/.local/bin:$PATH
