#!/bin/bash

# Get OUN of user
OUN=$(whoami)

# Get the UID corresponding to the current username
USER_ID=$(id -u "$OUN")

docker build --build-arg "OUN=$(whoami)" --build-arg "USER_ID=$(id -u "$OUN")" -t peyeon -f eyeon.Dockerfile .
docker run -it -v $(pwd):/workdir peyeon /bin/bash
