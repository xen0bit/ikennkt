# Interop tests

Docker-based interoperability tests that run veepin against a real peer and
prove a working tunnel with a cross-tunnel `ping`: **strongSwan** for IKEv2/ESP
(both directions), and the reference **wireguard-go** for WireGuard.

```sh
make interop
# or: go test -tags interop ./tests/interop/...
```

They are guarded by the `interop` build tag and need Docker, so they are
excluded from the default `go build`/`go test ./...` and add no module
dependency. Tests skip cleanly if Docker is unavailable.

## Scenarios

| Test | Client | Server | Ping |
|------|--------|--------|------|
| `TestInteropSelf` | `veepin connect ikev2` | `veepin serve ikev2` | `10.10.10.1` |
| `TestInteropVeepinClientStrongswanServer` (A) | `veepin connect ikev2` | strongSwan | `10.20.30.254` |
| `TestInteropStrongswanClientVeepinServer` (B) | strongSwan | `veepin serve ikev2` | `10.10.10.1` |
| `TestInteropVeepinClientWireguardServer` | `veepin connect wireguard` | wireguard-go | `10.10.10.1` |
| `TestInteropWireguardClientVeepinServer` | wireguard-go | `veepin serve wireguard` | `10.10.10.1` |
| `TestInteropWireguardSelf` | `veepin connect wireguard` | `veepin serve wireguard` | `10.10.10.1` |

## Layout

- `Dockerfile` (repo root) — veepin runtime image (static binaries + ip/iptables/ping).
- `strongswan/` — strongSwan image + swanctl configs for responder and initiator roles.
- `wireguard/` — reference wireguard-go image + wg-quick responder entrypoint.
- `veepin/` — entrypoints for `veepin serve` / `veepin connect`.
- `compose.*.yml` — one per scenario.
- `interop_test.go` — the `//go:build interop` harness (compose up → retry ping → down).

## Notes

- Both directions negotiate `aes256gcm16-prfsha256-curve25519` (IKE) /
  `aes256gcm16` (ESP) / PSK — the one suite veepin and strongSwan share.
- strongSwan needs its `openssl` plugin (`libstrongswan-standard-plugins`) for
  X25519, and `encap = yes` as an initiator (veepin has no raw-ESP path).
- `rp_filter=0` (set via compose `sysctls`) is required on the strongSwan side or
  the kernel drops XFRM-decrypted packets.
- A flat 2-container network suffices: the veepin client forces NAT-T, so no
  intermediate NAT router is needed.
- The WireGuard scenario uses **userspace** wireguard-go (via
  `WG_QUICK_USERSPACE_IMPLEMENTATION`), so it needs only `CAP_NET_ADMIN` and
  `/dev/net/tun` — no host WireGuard kernel module. Its keys are fixed test
  material baked into `compose.wireguard.yml`, a preshared key among them.
