#!/bin/sh
# veepin TOY server for the interop harness.
#
# -setup-nat brings the TUN up with the gateway address and installs
# forwarding/NAT, which is what makes the assigned client addresses reachable.
set -eu

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

echo "veepin-toy-server: starting on 0.0.0.0:${PORT:-5555}, pool ${POOL}"
exec veepin serve toy \
    -listen 0.0.0.0 \
    -port "${PORT:-5555}" \
    -pool "$POOL" \
    -user "$USER" \
    -insecure-shared-secret "$SECRET" \
    -tun toy0 \
    -setup-nat -wan eth0
