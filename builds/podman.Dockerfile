ARG LATEST_PYTHON_3_13=python:3.13-slim-bookworm
FROM $LATEST_PYTHON_3_13 AS builder

COPY builds/provision/ /provision/
RUN bash /provision/install-build-deps-debian.sh

ENV PATH="/root/.cargo/bin:$PATH"
RUN bash /provision/install-rust-binwalk.sh


RUN bash /provision/install-cmake.sh

RUN bash /provision/build-tlsh.sh

COPY . /src
RUN bash /provision/install-eyeon-venv.sh --venv /eye --src /src

#################################################

FROM $LATEST_PYTHON_3_13
COPY builds/provision/ /provision/
COPY --from=builder /opt/tlsh/bin /opt/tlsh/bin
COPY --from=builder /eye /eye
COPY --from=builder /root/.cargo/bin/binwalk /usr/local/bin/binwalk

RUN bash /provision/install-runtime-deps-debian-podman.sh \
    && bash /provision/install-sasquatch-deb.sh

ENV PATH="/eye/bin:$PATH"

# pull the plugin dbs, then remove Surfactant's root-owned temp state so the
# runtime user can recreate it as needed.
RUN bash /provision/warm-surfactant-dbs.sh

WORKDIR /workdir
