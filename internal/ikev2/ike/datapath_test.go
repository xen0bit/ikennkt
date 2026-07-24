package ike

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// gcmESPTransform builds an AES-GCM-16 ESP transform keyed with a repeated byte.
func gcmESPTransform(t *testing.T, key byte) esp.Transform {
	t.Helper()
	c, err := transform.Cipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	return esp.Transform{
		EncrID:    payload.ENCR_AES_GCM_16,
		EncrKeyLn: 256,
		EncKey:    bytes.Repeat([]byte{key}, c.KeyLen()),
	}
}

// TestESPTunnelNextHeaderByFamily proves the dual-stack data path tags each inner
// packet with the ESP next-header its version implies — IPv4 (4) or IPv6 (41) —
// so one Child SA carries both families and the receiver learns which it opened.
func TestESPTunnelNextHeaderByFamily(t *testing.T) {
	kOut := gcmESPTransform(t, 0x11)
	kIn := gcmESPTransform(t, 0x22)
	sender := &esp.SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &esp.SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	tun := &espTunnel{espSA: sender, inSPI: 0xbbbb}

	// A minimal IPv4 packet (version nibble 4) and IPv6 packet (nibble 6).
	v4 := make([]byte, 20)
	v4[0] = 0x45
	v6 := make([]byte, 40)
	v6[0] = 0x60

	for _, tc := range []struct {
		name   string
		pkt    []byte
		wantNH uint8
	}{
		{"IPv4 -> next-header 4", v4, 4},
		{"IPv6 -> next-header 41", v6, 41},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tun.Encapsulate(tc.pkt)
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			inner, nh, err := receiver.Decapsulate(wire)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if nh != tc.wantNH {
				t.Errorf("next-header = %d, want %d", nh, tc.wantNH)
			}
			if !bytes.Equal(inner, tc.pkt) {
				t.Errorf("inner packet did not round-trip")
			}
		})
	}
}
