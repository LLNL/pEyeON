FROM python:3.13.1-slim-bookworm AS builder

ARG USER_ID
ARG OUN

ENV DIE="3.10"

RUN apt-get update \
    && apt-get install -y \
       git make wget unzip build-essential python3 python3-dev python3-venv \
    && apt-get clean


RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3-linux-x86_64.sh \
    && chmod u+x cmake-3.30.3-linux-x86_64.sh \
    && mkdir /opt/cmake-3.30.3 \
    && ./cmake-3.30.3-linux-x86_64.sh --skip-license --prefix=/opt/cmake-3.30.3 \
    && rm cmake-3.30.3-linux-x86_64.sh \
    && ln -s /opt/cmake-3.30.3/bin/* /usr/local/bin

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

RUN python3 -m venv /eye && /eye/bin/pip install peyeon

RUN mkdir -p /opt/die && cd /opt/die \
    && wget https://github.com/horsicq/DIE-engine/releases/download/${DIE}/die_${DIE}_Ubuntu_24.04_amd64.deb

#################################################

FROM python:3.13.1-slim-bookworm
COPY --from=builder /opt/die/ /opt/die
COPY --from=builder /opt/tlsh/bin /opt/tlsh/bin
COPY --from=builder /eye /eye
ARG USER_ID
ARG OUN

ENV DIE="3.10"

RUN apt-get update \
    && apt-get install -y \
      libmagic1 ssdeep jq /opt/die/die_${DIE}_Ubuntu_24.04_amd64.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g $USER_ID $OUN \
    && useradd -ms /bin/bash $OUN -u $USER_ID -g $USER_ID

RUN chown -R $OUN /eye
USER $OUN
ENV PATH="/eye/bin:$PATH"

ENV PATH=/home/$OUN/.local/bin:$PATH

WORKDIR /workdir