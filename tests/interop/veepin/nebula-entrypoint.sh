#!/bin/sh
# veepin nebula host for the interop harness.
#
# Nebula has no client and no server, so both roles in this matrix run the same
# command; -am-lighthouse is the only thing that differs. The certificate this
# host presents was issued by the reference nebula-cert, and the address it uses
# is the one written into that certificate -- veepin does not choose it.
#
# `veepin connect` blocks once the host is running. Unlike the point-to-point
# protocols there is no peer whose reachability makes a useful readiness signal,
# so a failure here means the host itself would not start; retry in case the PKI
# volume was still being written.
set -u

PKI=/pki
until [ -f "$PKI/ready" ]; do
    echo "veepin-nebula: waiting for the PKI"
    sleep 1
done

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

lighthouse_flag=""
if [ -n "${LIGHTHOUSES:-}" ]; then
    lighthouse_flag="-lighthouses ${LIGHTHOUSES}"
fi
am_lighthouse_flag=""
if [ "${AM_LIGHTHOUSE:-false}" = "true" ]; then
    am_lighthouse_flag="-am-lighthouse"
fi
static_flag=""
if [ -n "${STATIC_HOSTS:-}" ]; then
    static_flag="-static-hosts ${STATIC_HOSTS}"
fi

echo "veepin-nebula: starting ${NAME} (lighthouse=${AM_LIGHTHOUSE:-false})"

i=1
while [ "$i" -le 30 ]; do
    # shellcheck disable=SC2086
    veepin connect nebula \
        -ca "$PKI/ca.crt" \
        -cert "$PKI/${NAME}.crt" \
        -key "$PKI/${NAME}.key" \
        -listen "0.0.0.0:${PORT:-4242}" \
        $static_flag \
        $lighthouse_flag \
        $am_lighthouse_flag \
        -tun nebula1 \
        -full-tunnel=false
    echo "veepin-nebula: attempt $i ended; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-nebula: giving up after $((i - 1)) attempts"
exit 1
