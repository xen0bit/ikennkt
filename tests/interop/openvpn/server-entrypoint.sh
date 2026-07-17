#!/bin/sh
# Start the reference OpenVPN server, ensuring the TUN device node exists. The
# config is selected by SERVER_CONF so one image serves every profile variant
# (plain GCM, tls-auth, tls-crypt, AES-256-CBC).
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
conf="${SERVER_CONF:-/server.conf}"
echo "openvpn-server: starting with $conf on udp/1194, tun 10.8.0.1"
exec openvpn --config "$conf"
