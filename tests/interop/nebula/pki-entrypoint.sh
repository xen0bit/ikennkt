#!/bin/sh
# Issues the throwaway PKI both ends of the nebula interop use, with the
# reference nebula-cert, into a volume the other services mount.
#
# The CA is generated per run and never leaves the container, so no key material
# lives in the repo. Every certificate here is issued by the reference tool
# rather than by veepin: veepin's certificate encoder has to match protobuf-go
# byte for byte, and the only way to prove that is to have it parse and verify
# certificates it did not produce.
set -eu

PKI=/pki
mkdir -p "$PKI"

# Start from a clean slate. The volume outlives a `compose up`, and nebula-cert
# refuses to overwrite an existing CA key, so a re-run would otherwise fail on
# the leftovers from the previous one. Clearing "ready" first also means a peer
# cannot start against a half-written PKI.
rm -f "$PKI/ready"
rm -f "$PKI"/*.crt "$PKI"/*.key

echo "nebula-pki: issuing CA"
nebula-cert ca -name "veepin-interop-ca" -duration 87600h \
    -out-crt "$PKI/ca.crt" -out-key "$PKI/ca.key"

for host in $HOSTS; do
    name=$(echo "$host" | cut -d= -f1)
    ip=$(echo "$host" | cut -d= -f2)
    echo "nebula-pki: issuing $name at $ip"
    nebula-cert sign \
        -ca-crt "$PKI/ca.crt" -ca-key "$PKI/ca.key" \
        -name "$name" -ip "$ip" \
        -out-crt "$PKI/$name.crt" -out-key "$PKI/$name.key"
done

# The private keys are read by an unprivileged process in another container.
chmod 0644 "$PKI"/*.crt "$PKI"/*.key

touch "$PKI/ready"
echo "nebula-pki: done"
ls -la "$PKI"
