ARG LATEST_PYTHON_3_13=python:3.13-slim
FROM $LATEST_PYTHON_3_13 AS builder

RUN apt-get update \
    && apt-get install -y \
       git make wget unzip curl build-essential clang pkg-config python3 python3-dev python3-venv \
       libfontconfig1-dev liblzma-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:$PATH"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal \
    && cargo install --git https://github.com/ReFirmLabs/binwalk --tag v3.1.0 binwalk


RUN arch=$(dpkg --print-architecture) \
    && case "$arch" in \
        amd64) cmake_arch=x86_64 ;; \
        arm64) cmake_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
    && cmake_version=3.30.3 \
    && cmake_installer="cmake-${cmake_version}-linux-${cmake_arch}.sh" \
    && wget "https://github.com/Kitware/CMake/releases/download/v${cmake_version}/${cmake_installer}" \
    && chmod u+x "$cmake_installer" \
    && mkdir -p "/opt/cmake-${cmake_version}" \
    && "./$cmake_installer" --skip-license --prefix="/opt/cmake-${cmake_version}" \
    && rm "$cmake_installer" \
    && ln -sf /opt/cmake-${cmake_version}/bin/* /usr/local/bin

RUN cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

COPY . /src
RUN python3 -m venv /eye \
    && /eye/bin/pip install --upgrade pip setuptools wheel \
    && /eye/bin/pip install /src

#################################################

FROM $LATEST_PYTHON_3_13
COPY --from=builder /opt/tlsh/bin /opt/tlsh/bin
COPY --from=builder /eye /eye
COPY --from=builder /root/.cargo/bin/binwalk /usr/local/bin/binwalk

RUN apt-get update \
    && apt-get install -y \
      libmagic1 ssdeep jq gosu curl 7zip zstd tar unzip sleuthkit cabextract lz4 lzop unar cpio device-tree-compiler \
      libfontconfig1 liblzma5 \
    && arch=$(dpkg --print-architecture) \
    && curl -fsSL -o /tmp/sasquatch.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_${arch}.deb" \
    && apt-get install -y /tmp/sasquatch.deb \
    && rm -f /tmp/sasquatch.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# look for entrypoint in basedir when pulling files
# or entrypoint from builds folder when cloning
COPY *entrypoint.sh *builds/*entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENV PATH="/eye/bin:$PATH"

# pull the plugin dbs, then remove Surfactant's root-owned temp state so the
# runtime user can recreate it as needed.
RUN surfactant plugin update-db --all \
    && rm -f /tmp/.surfactant_extracted_dirs.json

WORKDIR /workdir
ENTRYPOINT ["/entrypoint.sh"]
