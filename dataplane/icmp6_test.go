package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// makeV6Packet builds a minimal IPv6 packet of total length bytes (>= 40) from
// src to dst with a UDP next-header, zero-filled payload.
func makeV6Packet(t *testing.T, src, dst string, length int) []byte {
	t.Helper()
	if length < IPv6HeaderLen {
		t.Fatalf("length %d below IPv6 header", length)
	}
	pkt := make([]byte, length)
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(length-IPv6HeaderLen))
	pkt[6] = 17 // UDP
	pkt[7] = 64 // hop limit
	sa := netip.MustParseAddr(src).As16()
	da := netip.MustParseAddr(dst).As16()
	copy(pkt[8:24], sa[:])
	copy(pkt[24:40], da[:])
	return pkt
}

func TestNeedsFragmentationV6(t *testing.T) {
	big := makeV6Packet(t, "fd00::1", "fd00::2", 1500)
	if !NeedsFragmentation(big, 1400) {
		t.Error("oversized IPv6 packet should need a Packet Too Big")
	}
	small := makeV6Packet(t, "fd00::1", "fd00::2", 1200)
	if NeedsFragmentation(small, 1400) {
		t.Error("in-size IPv6 packet must not trigger a Packet Too Big")
	}
}

func TestFragNeededV6(t *testing.T) {
	orig := makeV6Packet(t, "2001:db8::1", "2001:db8::2", 1500)
	reply := FragNeeded(orig, 1400)
	if reply == nil {
		t.Fatal("FragNeeded returned nil for an oversized IPv6 packet")
	}

	// Outer IPv6 header: version 6, ICMPv6 next-header, addresses swapped.
	if reply[0]>>4 != 6 {
		t.Fatalf("reply is not IPv6 (first byte %#x)", reply[0])
	}
	if reply[6] != protoICMPv6 {
		t.Errorf("next-header = %d, want %d (ICMPv6)", reply[6], protoICMPv6)
	}
	src := netip.AddrFrom16([16]byte(reply[8:24]))
	dst := netip.AddrFrom16([16]byte(reply[24:40]))
	if want := netip.MustParseAddr("2001:db8::2"); src != want {
		t.Errorf("reply src = %s, want original dst %s", src, want)
	}
	if want := netip.MustParseAddr("2001:db8::1"); dst != want {
		t.Errorf("reply dst = %s, want original src %s", dst, want)
	}

	// ICMPv6 Packet Too Big body: type 2, carrying the MTU.
	icmp := reply[IPv6HeaderLen:]
	if icmp[0] != icmp6TypePacketTooBig || icmp[1] != 0 {
		t.Errorf("icmp type/code = %d/%d, want %d/0", icmp[0], icmp[1], icmp6TypePacketTooBig)
	}
	if got := binary.BigEndian.Uint32(icmp[4:8]); got != 1400 {
		t.Errorf("advertised MTU = %d, want 1400", got)
	}

	// The checksum must verify: recomputing over the pseudo-header + message
	// with the stored checksum in place yields zero.
	if !icmpv6ChecksumValid(reply[8:24], reply[24:40], icmp) {
		t.Error("ICMPv6 checksum does not verify")
	}

	// The reply must never exceed the IPv6 minimum MTU (RFC 4443 §3.2).
	if len(reply) > MinIPv6MTU {
		t.Errorf("reply length %d exceeds IPv6 minimum MTU %d", len(reply), MinIPv6MTU)
	}
}

func TestFragNeededV6FloorsMTU(t *testing.T) {
	// A tunnel MTU below the IPv6 minimum must still advertise at least 1280.
	orig := makeV6Packet(t, "fd00::1", "fd00::2", 1400)
	reply := FragNeeded(orig, 900)
	if reply == nil {
		t.Fatal("FragNeeded returned nil")
	}
	if got := binary.BigEndian.Uint32(reply[IPv6HeaderLen+4 : IPv6HeaderLen+8]); got != MinIPv6MTU {
		t.Errorf("advertised MTU = %d, want floor %d", got, MinIPv6MTU)
	}
}

// icmpv6ChecksumValid recomputes the ICMPv6 checksum over the pseudo-header and
// message (with the stored checksum left in place) and reports whether it folds
// to zero, the standard receiver-side validation.
func icmpv6ChecksumValid(src, dst, icmp []byte) bool {
	var pseudo [40]byte
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = protoICMPv6
	sum := checksumAccumulate(0, pseudo[:])
	sum = checksumAccumulate(sum, icmp)
	return checksumFold(sum) == 0
}
