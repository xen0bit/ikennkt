package masque

import (
	"bytes"
	"net/netip"
	"testing"
)

// Capsules written back-to-back must read back one at a time from the byte
// stream, since the peer is free to pack or split them across DATA frames.
func TestCapsuleStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	assign := EncodeAddresses([]AddressEntry{{RequestID: 1, Prefix: netip.MustParsePrefix("10.0.0.2/32")}})
	route := EncodeRoutes([]RouteEntry{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: 0}})
	dgram := EncodeDatagramPayload([]byte{0x45, 0x00, 0x00, 0x1c})

	for _, c := range []struct {
		typ   uint64
		value []byte
	}{
		{CapsuleAddressAssign, assign},
		{CapsuleRouteAdvertisement, route},
		{CapsuleDatagram, dgram},
	} {
		if err := WriteCapsule(&buf, c.typ, c.value); err != nil {
			t.Fatalf("WriteCapsule: %v", err)
		}
	}

	wantTypes := []uint64{CapsuleAddressAssign, CapsuleRouteAdvertisement, CapsuleDatagram}
	wantVals := [][]byte{assign, route, dgram}
	for i := range wantTypes {
		c, err := ReadCapsule(&buf)
		if err != nil {
			t.Fatalf("ReadCapsule %d: %v", i, err)
		}
		if c.Type != wantTypes[i] {
			t.Errorf("capsule %d type = %#x, want %#x", i, c.Type, wantTypes[i])
		}
		if !bytes.Equal(c.Value, wantVals[i]) {
			t.Errorf("capsule %d value = % x, want % x", i, c.Value, wantVals[i])
		}
	}
}

// A capsule advertising a value larger than the ceiling is refused before the
// length is allocated, so a hostile header cannot force a huge allocation.
func TestReadCapsuleRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	// type 0, then a length varint well past maxCapsuleValue, then nothing.
	buf.Write([]byte{0x00})
	buf.Write([]byte{0x80, 0x20, 0x00, 0x00}) // 4-byte varint = 0x200000 = 2 MiB
	if _, err := ReadCapsule(&buf); err == nil {
		t.Error("accepted an oversize capsule length")
	}
}
