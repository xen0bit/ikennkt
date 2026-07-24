#!/bin/sh
# strongSwan responder with certificate (pubkey) authentication (Direction A:
# veepin ikev2 client -> strongSwan server). It mints a throwaway ECDSA PKI —
# a CA, a server certificate, and a client certificate — into the shared /pki
# volume, installs its own cert into swanctl, and serves. The veepin client
# reads its client cert/key and the CA from /pki.
set -e

PKI=/pki
mkdir -p "$PKI"

# --- Generate the PKI once (ECDSA P-256, method 14 ecdsa-with-SHA256). ---
if [ ! -f "$PKI/ready" ]; then
    pki --gen --type ecdsa --size 256 --outform pem > "$PKI/ca-key.pem"
    pki --self --in "$PKI/ca-key.pem" --type ecdsa \
        --dn "CN=veepin test CA" --ca --outform pem > "$PKI/ca-cert.pem"

    pki --gen --type ecdsa --size 256 --outform pem > "$PKI/server-key.pem"
    pki --pub --in "$PKI/server-key.pem" --type ecdsa \
        | pki --issue --cacert "$PKI/ca-cert.pem" --cakey "$PKI/ca-key.pem" \
            --dn "CN=vpn.example.com" --san vpn.example.com \
            --flag serverAuth --outform pem > "$PKI/server-cert.pem"

    pki --gen --type ecdsa --size 256 --outform pem > "$PKI/client-key.pem"
    pki --pub --in "$PKI/client-key.pem" --type ecdsa \
        | pki --issue --cacert "$PKI/ca-cert.pem" --cakey "$PKI/ca-key.pem" \
            --dn "CN=client.example.com" --san client.example.com \
            --flag clientAuth --outform pem > "$PKI/client-cert.pem"
fi

# Install the CA + server credentials where swanctl looks for them.
mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
cp "$PKI/ca-cert.pem" /etc/swanctl/x509ca/
cp "$PKI/server-cert.pem" /etc/swanctl/x509/
cp "$PKI/server-key.pem" /etc/swanctl/private/

# In-tunnel, pingable address on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
# Signal the client that the PKI is complete and loadable.
touch "$PKI/ready"
echo "strongswan-server: pubkey config loaded; ready as responder (id=vpn.example.com)"

wait "$CHARON"
