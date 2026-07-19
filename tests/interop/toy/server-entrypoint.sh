#!/bin/sh
# The independent TOY server for the interop harness.
set -eu

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

echo "toy-server: starting on 0.0.0.0:${PORT:-5555}, gateway ${GATEWAY}"
exec toypeer server \
    --listen "0.0.0.0:${PORT:-5555}" \
    --user "$USER" \
    --secret "$SECRET" \
    --tun toy0 \
    --pool-base "$POOL_BASE" \
    --gateway "$GATEWAY"
