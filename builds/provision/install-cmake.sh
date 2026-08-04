#!/usr/bin/env bash

set -euo pipefail

cmake_version="${CMAKE_VERSION:-3.30.3}"

arch=$(dpkg --print-architecture)
case "$arch" in
  amd64) cmake_arch=x86_64 ;;
  arm64) cmake_arch=aarch64 ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac

cmake_installer="cmake-${cmake_version}-linux-${cmake_arch}.sh"

curl -fsSLO "https://github.com/Kitware/CMake/releases/download/v${cmake_version}/${cmake_installer}"
chmod u+x "$cmake_installer"

mkdir -p "/opt/cmake-${cmake_version}"
"./$cmake_installer" --skip-license --prefix="/opt/cmake-${cmake_version}"
rm -f "$cmake_installer"

ln -sf "/opt/cmake-${cmake_version}/bin"/* /usr/local/bin
