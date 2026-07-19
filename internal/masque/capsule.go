// Package masque implements MASQUE CONNECT-IP (RFC 9484): IP-over-HTTP/3.
//
// The HTTP/3 substrate lives in the http3 subpackage; this package is the
// CONNECT-IP protocol on top of it — the capsule types that assign an address
// and advertise a route, the HTTP-Datagram payload that carries an inner IP
// packet, and the client and server roles that turn a request stream into a
// tunnel.
//
// Because x/net/quic has no QUIC DATAGRAM frames, veepin runs in capsule mode:
// every inner packet is a DATAGRAM capsule on the request stream rather than an
// unreliable QUIC datagram. That is a documented performance boundary, not a
// correctness one; the capsule formats are identical either way.
package masque

import (
	"errors"
	"fmt"
	"io"

	"github.com/xen0bit/veepin/internal/masque/http3"
)

// Capsule type codes (RFC 9297 for DATAGRAM, RFC 9484 §4 for the rest).
const (
	CapsuleDatagram           = 0x00
	CapsuleAddressAssign      = 0x01
	CapsuleAddressRequest     = 0x02
	CapsuleRouteAdvertisement = 0x03
)

// maxCapsuleValue bounds a capsule this code will buffer. A DATAGRAM capsule
// carries one inner packet; the control capsules are a handful of addresses.
// 64 KiB is above any of these and stops a hostile length from forcing an
// unbounded allocation, the same ceiling the HTTP/3 frame layer uses.
const maxCapsuleValue = 1 << 16

// ErrCapsuleTooLarge reports a capsule whose length exceeds what will be
// buffered.
var ErrCapsuleTooLarge = errors.New("masque: capsule value exceeds the maximum")

// Capsule is a decoded capsule: its type and its value bytes.
type Capsule struct {
	Type  uint64
	Value []byte
}

// WriteCapsule writes one capsule as a type/length/value tuple. w is a
// RequestStream, whose Write delivers these bytes as one HTTP/3 DATA frame; the
// peer may reframe, which is why ReadCapsule streams rather than assuming the
// framing.
func WriteCapsule(w io.Writer, typ uint64, value []byte) error {
	hdr := http3.AppendVarint(nil, typ)
	hdr = http3.AppendVarint(hdr, uint64(len(value)))
	buf := append(hdr, value...)
	_, err := w.Write(buf)
	return err
}

// ReadCapsule reads one capsule from the capsule byte stream. A value larger
// than maxCapsuleValue is refused before it is allocated.
func ReadCapsule(r io.Reader) (Capsule, error) {
	typ, err := http3.ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	length, err := http3.ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	if length > maxCapsuleValue {
		return Capsule{}, fmt.Errorf("%w: %d octets", ErrCapsuleTooLarge, length)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return Capsule{}, err
	}
	return Capsule{Type: typ, Value: value}, nil
}
