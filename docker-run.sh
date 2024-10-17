#!/bin/bash

container_name="eyeon"

# check to see if container already exists
result=$(docker ps -a -q -f name=$container_name)

if [ "$result" ]; then
    # Container already exists--launch the stopped container
    docker start "$container_name"
    docker exec -it eyeon /bin/bash
else
    # Doesn't exist, creates a new container called eyeon
    docker run --name "$container_name" -p8888:8888 -p8501:8501 -it -v $(pwd):/workdir peyeon /bin/bash
fi
