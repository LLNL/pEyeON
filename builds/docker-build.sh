#!/bin/bash

podman build -t peyeon -f ubi8.Dockerfile .
# for docker use this line:
# docker build --build-arg "OUN=$(whoami)" --build-arg "USER_ID=$(id -u $OUN)" -t peyeon -f ubi8.Dockerfile .
