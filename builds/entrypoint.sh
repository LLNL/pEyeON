#!/bin/bash

set -e

# Get owner of the mounted volume
VOLUME_UID=$(stat -c '%u' /workdir)
VOLUME_GID=$(stat -c '%g' /workdir)

# Create user with same UID/GID if it doesn't match root
if [ "$VOLUME_UID" != "0" ]; then
    # Create group if it doesn't exist
    if ! getent group $VOLUME_GID > /dev/null 2>&1; then
        groupadd -g $VOLUME_GID eyeon
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd $VOLUME_UID > /dev/null 2>&1; then
        useradd -u $VOLUME_UID -g $VOLUME_GID -s /bin/bash -m eyeon
    fi
    
    # Run the command as the appropriate user
    exec gosu $VOLUME_UID:$VOLUME_GID "$@"
else
    # If volume is owned by root, run as non-root default user
    useradd -u 1000 -g 1000 -s /bin/bash -m eyeon
    exec gosu eyeon "$@"
fi