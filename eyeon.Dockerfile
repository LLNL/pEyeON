FROM amd64/ubuntu:25.04

RUN userdel -r ubuntu  # get rid of default user 

ARG USER_ID
ARG OUN

RUN apt-get update \
    && apt-get install -y \
      python3 python3-pip python3-dev python3-venv python3-build \
      libmagic1 git make wget unzip build-essential vim ssdeep jq curl \
    && apt-get clean
RUN groupadd -g $USER_ID $OUN \
    && useradd -ms /bin/bash $OUN -u $USER_ID -g $USER_ID

RUN echo "alias build='python3 -m build'" >> /home/$OUN/.bashrc \
    && echo "alias clean='rm -rf /workdir/dist'" >> /home/$OUN/.bashrc \
    && echo "alias rein='build && pip uninstall -y eyeon && pip install /workdir/dist/peyeon*.whl'" >> /home/$OUN/.bashrc \
    && echo "alias eye='source /eye/bin/activate'" >> /home/$OUN/.bashrc

RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3-linux-x86_64.sh \
    && chmod u+x cmake-3.30.3-linux-x86_64.sh \
    && mkdir /opt/cmake-3.30.3 \
    && ./cmake-3.30.3-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.30.3 \
    && rm cmake-3.30.3-linux-x86_64.sh \
    && ln -s /opt/cmake-3.30.3/bin/* /usr/local/bin

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh


RUN mkdir -p /opt/die \
    && curl -L -o /opt/die/die_3.10_Ubuntu_24.04_amd64.deb https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb \
    && apt-get install -y /opt/die/die_3.10_Ubuntu_24.04_amd64.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /eye && chown -R $OUN /eye
USER $OUN


ENV PATH=/home/$OUN/.local/bin:$PATH
