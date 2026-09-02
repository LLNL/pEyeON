#!/usr/bin/env bash

set -euo pipefail

# The VM intentionally uses systemd-networkd for DHCP rather than the default
# Debian/cloud-init networking path. Keep this file as the single active
# network configuration installed by the VM provisioning flow.
#
# A static example is shipped separately in the VM quickstart. It is not placed
# in /etc/systemd/network, so it cannot accidentally override this DHCP file.

mkdir -p /etc/systemd/network

cat > /etc/systemd/network/20-eyeon-dhcp.network <<'EOF'
[Match]
Name=en*

[Network]
DHCP=yes

[DHCP]
UseDNS=yes
EOF

systemctl enable --now systemd-networkd

# Keep name resolution consistent with systemd-networkd when systemd-resolved
# is available in the guest image.
systemctl enable --now systemd-resolved || true
