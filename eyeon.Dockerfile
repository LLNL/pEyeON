FROM ubuntu

RUN apt update \
    && apt install -y python3 python3-pip python3-dev python3-venv libmagic1 git make wget unzip build-essential vim ssdeep jq \
    && groupadd -g 50001 xyz \
    && useradd -ms /bin/bash xyz -u 50001 -g 50001 \
    && pip3 install build sphinx pre-commit black

RUN echo "alias build='python3 -m build'" >> /home/xyz/.bashrc \
    && echo "alias clean='rm -rf /workdir/dist'" >> /home/xyz/.bashrc \
    && echo "alias rein='build && pip uninstall -y eyeon && pip install /workdir/dist/eyeon*.whl'" >> /home/xyz/.bashrc 

RUN wget https://github.com/Kitware/CMake/releases/download/v3.27.4/cmake-3.27.4-linux-x86_64.sh \
    && chmod u+x cmake-3.27.4-linux-x86_64.sh \
    && mkdir /opt/cmake-3.27.4 \
    && ./cmake-3.27.4-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.27.4 \
    && rm cmake-3.27.4-linux-x86_64.sh \
    && ln -s /opt/cmake-3.27.4/bin/* /usr/local/bin

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

RUN pip3 install telfhash

USER xyz
