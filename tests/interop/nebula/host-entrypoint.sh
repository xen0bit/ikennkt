#!/bin/sh
# Reference nebula host for the interop harness.
#
# It runs the real slackhq/nebula daemon against a config this harness writes,
# so the veepin peer is talking to an implementation it shares no code with:
# the Noise_IX handshake, the 16-octet header, the AEAD data path and the
# lighthouse protocol all have to match for a ping to cross.
#
# The firewall is left wide open because veepin does not implement nebula's
# ACL engine; the test is about the protocol, not the policy layer.
set -eu

PKI=/pki
until [ -f "$PKI/ready" ]; do
    echo "nebula-host: waiting for the PKI"
    sleep 1
done

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

# STATIC_HOSTS is "overlay=hostname:port" entries separated by spaces; empty for
# a lighthouse, which everyone else finds statically.
static_yaml=""
for entry in ${STATIC_HOSTS:-}; do
    overlay=$(echo "$entry" | cut -d= -f1)
    under=$(echo "$entry" | cut -d= -f2)
    static_yaml="${static_yaml}  \"${overlay}\": [\"${under}\"]
"
done
if [ -z "$static_yaml" ]; then
    static_yaml="  {}"
    static_block="static_host_map: {}"
else
    static_block="static_host_map:
${static_yaml}"
fi

lighthouse_hosts=""
for lh in ${LIGHTHOUSE_HOSTS:-}; do
    lighthouse_hosts="${lighthouse_hosts}    - \"${lh}\"
"
done
if [ -z "$lighthouse_hosts" ]; then
    lighthouse_hosts="  hosts: []"
else
    lighthouse_hosts="  hosts:
${lighthouse_hosts}"
fi

cat >/config.yml <<EOF
pki:
  ca: ${PKI}/ca.crt
  cert: ${PKI}/${NAME}.crt
  key: ${PKI}/${NAME}.key

${static_block}

lighthouse:
  am_lighthouse: ${AM_LIGHTHOUSE:-false}
  interval: 5
${lighthouse_hosts}

listen:
  host: 0.0.0.0
  port: ${PORT:-4242}

punchy:
  punch: true
  delay: 1s

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

logging:
  level: info
  format: text

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
EOF

echo "nebula-host: starting ${NAME} with config:"
cat /config.yml

exec nebula -config /config.yml
