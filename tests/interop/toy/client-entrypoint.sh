#!/bin/sh
# The independent TOY client for the interop harness, dialling the veepin
# server. It retries until the server is listening.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "toy-client: connecting to ${SERVER}:${PORT:-5555} (attempt $i)"
    toypeer client \
        --server "${SERVER}:${PORT:-5555}" \
        --user "$USER" \
        --secret "$SECRET" \
        --tun toy0
    echo "toy-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
