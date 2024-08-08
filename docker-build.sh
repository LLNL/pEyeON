#!/bin/bash

docker build --no-cache --build-arg "OUN=$(whoami)" --build-arg "USER_ID=$(id -u $OUN)" -t peyeon -f eyeon.Dockerfile .
