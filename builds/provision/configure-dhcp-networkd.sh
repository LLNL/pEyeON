#!/usr/bin/env bash

set -euo pipefail

# Ensure a simple, robust DHCP client config on "en*" interfaces.
# This avoids relying on cloud-init's networking behavior, which can vary by
# image and hypervisor.

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

# Optional, but commonly useful for name resolution consistency.
systemctl enable --now systemd-resolved || true
