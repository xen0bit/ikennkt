package http3

import "testing"

// Fuzz targets for the HTTP/3 substrate. These parsers read bytes off a QUIC
// stream from a peer that may be hostile or simply broken; a panic on malformed
// input is a denial of service regardless of what rides above. The invariant in
// each case is the same: reject cleanly or round-trip, never crash.

func FuzzConsumeVarint(f *testing.F) {
	f.Add([]byte{0x25})
	f.Add([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c})
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		v, rest, err := ConsumeVarint(data)
		if err != nil {
			return
		}
		// RFC 9000 §16: a decoder must accept a value in a longer encoding than
		// necessary, so the number of octets consumed may exceed the canonical
		// length. The canonical form must therefore be no *longer* than what was
		// on the wire, and must itself round-trip to the same value -- but it is
		// not required to equal the input bytes.
		consumed := len(data) - len(rest)
		enc := AppendVarint(nil, v)
		if len(enc) > consumed {
			t.Fatalf("varint %d: canonical encoding %d octets exceeds the %d consumed", v, len(enc), consumed)
		}
		v2, rest2, err := ConsumeVarint(enc)
		if err != nil || v2 != v || len(rest2) != 0 {
			t.Fatalf("canonical re-decode of %d: got %d rest %d err %v", v, v2, len(rest2), err)
		}
	})
}

func FuzzParseSettings(f *testing.F) {
	f.Add(DefaultSettings().Encode())
	f.Add([]byte{})
	f.Add([]byte{0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		if s, err := ParseSettings(data); err == nil {
			// A parsed SETTINGS frame re-encodes; the result must itself parse.
			if _, err := ParseSettings(s.Encode()); err != nil {
				t.Fatalf("re-parse of encoded settings failed: %v", err)
			}
		}
	})
}

func FuzzDecodeFieldSection(f *testing.F) {
	f.Add(EncodeFieldSection([]Field{{":method", "CONNECT"}, {":protocol", "connect-ip"}}))
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only requirement is that it does not panic on arbitrary input.
		_, _ = DecodeFieldSection(data)
	})
}
