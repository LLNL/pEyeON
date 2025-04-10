#!/bin/bash

container_name="eyeon"

# check to see if container already exists
result=$(podman ps -a -q -f name=$container_name)

if [ "$result" ]; then
    # Container already exists--launch the stopped container
    podman start "$container_name"
    podman exec -it eyeon /bin/bash
else
    # Doesn't exist, creates a new container called eyeon
    podman run --name "$container_name" -p8888:8888 -p8501:8501 -it -v $(pwd):/workdir:rw  peyeon /bin/bash
fi
