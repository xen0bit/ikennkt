package http3

import (
	"testing"

	"golang.org/x/net/http2/hpack"
)

func fieldsEqual(a, b []Field) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A CONNECT-IP request header section, round-tripped. The pseudo-headers that
// match the static table exactly must survive, and the literal :authority and
// :path must come back byte-for-byte.
func TestQPACKConnectRequestRoundTrip(t *testing.T) {
	req := []Field{
		{":method", "CONNECT"},
		{":scheme", "https"},
		{":authority", "proxy.example:443"},
		{":path", "/.well-known/masque/ip/*/*/"},
		{":protocol", "connect-ip"},
		{"capsule-protocol", "?1"},
	}
	enc := EncodeFieldSection(req)
	got, err := DecodeFieldSection(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !fieldsEqual(got, req) {
		t.Errorf("round trip mismatch:\n got %v\nwant %v", got, req)
	}
}

// The CONNECT response is a single static-table :status plus a literal. A
// :status 200 must encode to the one-byte indexed line, proving the static
// path is taken rather than a literal.
func TestQPACKStatusIsIndexed(t *testing.T) {
	enc := EncodeFieldSection([]Field{{":status", "200"}})
	// prefix is two zero octets; the field line should then be a single byte
	// with the 1_1 static-indexed pattern.
	if len(enc) != 3 {
		t.Fatalf(":status 200 encoded to %d bytes (% x), want a 2-byte prefix + 1-byte indexed line", len(enc), enc)
	}
	if enc[2]&0xc0 != 0xc0 {
		t.Errorf("field line %#02x is not a static indexed field line", enc[2])
	}
	got, err := DecodeFieldSection(enc)
	if err != nil || len(got) != 1 || got[0] != (Field{":status", "200"}) {
		t.Errorf("decode = %v, %v", got, err)
	}
}

// A real HTTP/3 proxy is free to Huffman-code its literals. The decoder must
// handle that, so this builds a block whose literal value is Huffman-coded with
// the reference encoder and checks it decodes back.
func TestQPACKDecodesHuffmanLiterals(t *testing.T) {
	// Literal Field Line With Literal Name, Huffman on both name and value.
	name := "capsule-protocol"
	value := "?1"

	var block []byte
	block = append(block, 0x00, 0x00) // field-section prefix

	// 0010_1xxx: literal name, N=0, H=1, 3-bit name length prefix.
	huffName := hpack.AppendHuffmanString(nil, name)
	block = appendPrefixedInt(block, uint64(len(huffName)), 3, 0x28)
	block = append(block, huffName...)

	// value: 1xxx_xxxx H=1, 7-bit length prefix.
	huffVal := hpack.AppendHuffmanString(nil, value)
	block = appendPrefixedInt(block, uint64(len(huffVal)), 7, 0x80)
	block = append(block, huffVal...)

	got, err := DecodeFieldSection(block)
	if err != nil {
		t.Fatalf("decode huffman: %v", err)
	}
	want := []Field{{name, value}}
	if !fieldsEqual(got, want) {
		t.Errorf("huffman decode = %v, want %v", got, want)
	}
}

// A block that references the dynamic table must be rejected rather than
// mis-decoded: this decoder advertises zero capacity, so such a reference is a
// peer bug that has to surface, not be guessed past.
func TestQPACKRejectsDynamicReference(t *testing.T) {
	// prefix with a non-zero required insert count.
	if _, err := DecodeFieldSection([]byte{0x01, 0x00}); err == nil {
		t.Error("accepted a non-zero required insert count")
	}
	// A dynamic indexed field line: 1_0_xxxxxx (T bit clear).
	if _, err := DecodeFieldSection([]byte{0x00, 0x00, 0x80}); err == nil {
		t.Error("accepted a dynamic indexed field line")
	}
}

func TestQPACKPrefixedIntRoundTrip(t *testing.T) {
	for _, n := range []uint{3, 4, 5, 6, 7} {
		for _, v := range []uint64{0, 1, 10, 63, 64, 127, 128, 255, 1000, 100000} {
			enc := appendPrefixedInt(nil, v, n, 0)
			got, rest, err := readPrefixedInt(enc, n)
			if err != nil || got != v || len(rest) != 0 {
				t.Errorf("prefixed int n=%d v=%d: got %d rest %d err %v", n, v, got, len(rest), err)
			}
		}
	}
}
