#!/bin/sh
# strongSwan responder entrypoint, dual-stack. Same as server-entrypoint.sh but
# also puts an IPv6 in-tunnel target on lo (inside the v6 local_ts) so the veepin
# client can prove the IPv6 half of the tunnel with a ping.
set -e

# In-tunnel, pingable addresses on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true
ip -6 addr add fd00:20:30::254/128 dev lo 2>/dev/null || true

# Start charon in the background, wait for its vici socket, then load config.
/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-server: config loaded; ready as responder (id=vpn.example.com, dual-stack)"

wait "$CHARON"
