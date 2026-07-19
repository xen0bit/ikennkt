package http3

import (
	"bytes"
	"testing"
)

// The sample encodings from RFC 9000 Appendix A.1. Decoding these exact byte
// strings to these exact values is what makes the codec interoperable; a
// hand-rolled varint that is subtly wrong passes every round-trip test against
// itself and fails against every real QUIC peer.
func TestVarintRFCVectors(t *testing.T) {
	for _, tc := range []struct {
		enc []byte
		val uint64
	}{
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x25}, 37},
		// RFC 9000 also shows 37 encoded in two octets, to make the point that
		// the length is chosen by the sender: a decoder must accept it.
		{[]byte{0x40, 0x25}, 37},
	} {
		got, rest, err := ConsumeVarint(tc.enc)
		if err != nil {
			t.Errorf("ConsumeVarint(% x): %v", tc.enc, err)
			continue
		}
		if got != tc.val {
			t.Errorf("ConsumeVarint(% x) = %d, want %d", tc.enc, got, tc.val)
		}
		if len(rest) != 0 {
			t.Errorf("ConsumeVarint(% x) left %d bytes", tc.enc, len(rest))
		}
	}
}

// The encoder must pick the shortest length, so its output round-trips and
// matches the canonical single-length vectors from the RFC.
func TestVarintEncodeShortest(t *testing.T) {
	for _, tc := range []struct {
		val uint64
		enc []byte
	}{
		{37, []byte{0x25}},
		{15293, []byte{0x7b, 0xbd}},
		{494878333, []byte{0x9d, 0x7f, 0x3e, 0x7d}},
		{151288809941952652, []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}},
		{0, []byte{0x00}},
		{63, []byte{0x3f}},       // largest 1-byte
		{64, []byte{0x40, 0x40}}, // smallest 2-byte
		{maxVarint, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		got := AppendVarint(nil, tc.val)
		if !bytes.Equal(got, tc.enc) {
			t.Errorf("AppendVarint(%d) = % x, want % x", tc.val, got, tc.enc)
		}
		if VarintLen(tc.val) != len(tc.enc) {
			t.Errorf("VarintLen(%d) = %d, want %d", tc.val, VarintLen(tc.val), len(tc.enc))
		}
	}
}

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 62, 63, 64, 16382, 16383, 16384, 1073741822, 1073741823, 1073741824, maxVarint} {
		enc := AppendVarint(nil, v)
		got, rest, err := ConsumeVarint(enc)
		if err != nil || got != v || len(rest) != 0 {
			t.Errorf("round trip %d: got %d rest %d err %v", v, got, len(rest), err)
		}
		r, err := ReadVarint(bytes.NewReader(enc))
		if err != nil || r != v {
			t.Errorf("ReadVarint %d: got %d err %v", v, r, err)
		}
	}
}

func TestVarintTruncated(t *testing.T) {
	// A first byte announcing an 8-octet value with only 3 present is a
	// truncation the decoder must reject rather than read past.
	if _, _, err := ConsumeVarint([]byte{0xc2, 0x19, 0x7c}); err == nil {
		t.Error("accepted a truncated 8-octet varint")
	}
	if _, _, err := ConsumeVarint(nil); err == nil {
		t.Error("accepted an empty buffer")
	}
}
