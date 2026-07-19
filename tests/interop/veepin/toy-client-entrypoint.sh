#!/bin/sh
# veepin TOY client for the interop harness, dialling the independent Python
# peer. `veepin connect` blocks once up; if the server is not ready it fails
# fast, so retry until it answers.
#
# -full-tunnel=false brings the TUN up with just the assigned address and the
# connected route, so a ping to the server's gateway crosses the tunnel without
# hijacking the container's default route.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-toy-client: connecting to ${SERVER}:${PORT:-5555} (attempt $i)"
    veepin connect toy \
        -server "$SERVER" \
        -port "${PORT:-5555}" \
        -user "$USER" \
        -insecure-shared-secret "$SECRET" \
        -tun toy0 \
        -full-tunnel=false
    echo "veepin-toy-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
