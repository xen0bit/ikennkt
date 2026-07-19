package masque

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/internal/masque/http3"
)

// Byte-exact, because these layouts are transcribed from RFC 9484 and the whole
// point is that a real proxy agrees with them. A round-trip test alone would
// pass even if every field were the wrong width.

func TestDatagramPayloadLayout(t *testing.T) {
	ip := []byte{0x45, 0x00, 0x00, 0x14}
	got := EncodeDatagramPayload(ip)
	// context ID 0 is a single 0x00 varint, then the packet verbatim.
	want := append([]byte{0x00}, ip...)
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeDatagramPayload = % x, want % x", got, want)
	}

	back, ok, err := DecodeDatagramPayload(got)
	if err != nil || !ok {
		t.Fatalf("DecodeDatagramPayload ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(back, ip) {
		t.Errorf("decoded packet = % x, want % x", back, ip)
	}
}

func TestDatagramPayloadRejectsOtherContext(t *testing.T) {
	// Context ID 2 (a client-allocated context we never negotiate) is not an IP
	// packet; it must be reported as such, not handed to the TUN.
	_, ok, err := DecodeDatagramPayload([]byte{0x02, 0xde, 0xad})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("a non-zero context ID was accepted as an IP packet")
	}
}

func TestAddressEntryLayout(t *testing.T) {
	e := AddressEntry{RequestID: 1, Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	got := EncodeAddresses([]AddressEntry{e})
	want := []byte{
		0x01,                   // Request ID
		0x04,                   // IP Version 4
		0x0a, 0x00, 0x00, 0x01, // 10.0.0.1
		0x20, // prefix length 32
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeAddresses = % x, want % x", got, want)
	}

	back, err := ParseAddresses(got)
	if err != nil {
		t.Fatalf("ParseAddresses: %v", err)
	}
	if len(back) != 1 || back[0] != e {
		t.Errorf("round trip = %v, want %v", back, e)
	}
}

func TestAddressEntryIPv6(t *testing.T) {
	e := AddressEntry{RequestID: 7, Prefix: netip.MustParsePrefix("2001:db8::1/128")}
	got := EncodeAddresses([]AddressEntry{e})
	if got[1] != 6 {
		t.Fatalf("IP version octet = %d, want 6", got[1])
	}
	// Request ID (1) + version (1) + address (16) + prefix (1) = 19.
	if len(got) != 19 {
		t.Fatalf("encoded length = %d, want 19", len(got))
	}
	back, err := ParseAddresses(got)
	if err != nil || len(back) != 1 || back[0] != e {
		t.Errorf("round trip = %v (%v), want %v", back, err, e)
	}
}

func TestMultipleAddresses(t *testing.T) {
	entries := []AddressEntry{
		{RequestID: 1, Prefix: netip.MustParsePrefix("10.0.0.5/32")},
		{RequestID: 2, Prefix: netip.MustParsePrefix("10.0.0.6/32")},
	}
	back, err := ParseAddresses(EncodeAddresses(entries))
	if err != nil {
		t.Fatalf("ParseAddresses: %v", err)
	}
	if len(back) != 2 || back[0] != entries[0] || back[1] != entries[1] {
		t.Errorf("round trip = %v, want %v", back, entries)
	}
}

func TestRouteLayout(t *testing.T) {
	r := RouteEntry{
		Start:    netip.MustParseAddr("10.0.0.0"),
		End:      netip.MustParseAddr("10.0.0.255"),
		Protocol: 0,
	}
	got := EncodeRoutes([]RouteEntry{r})
	want := []byte{
		0x04,                   // IP Version 4
		0x0a, 0x00, 0x00, 0x00, // start 10.0.0.0
		0x0a, 0x00, 0x00, 0xff, // end 10.0.0.255
		0x00, // protocol 0 = all
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeRoutes = % x, want % x", got, want)
	}
	back, err := ParseRoutes(got)
	if err != nil || len(back) != 1 || back[0] != r {
		t.Errorf("round trip = %v (%v), want %v", back, err, r)
	}
}

func TestParseAddressesRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"truncated address", []byte{0x01, 0x04, 0x0a, 0x00}},
		{"bad version", []byte{0x01, 0x05, 0x00}},
		{"prefix over address", []byte{0x01, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x40}},
		{"missing prefix len", []byte{0x01, 0x04, 0x0a, 0x00, 0x00, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAddresses(tc.b); err == nil {
				t.Error("accepted a malformed address list")
			}
		})
	}
}

func TestConnectIPPath(t *testing.T) {
	if got := ConnectIPPath("", ""); got != "/.well-known/masque/ip/*/*/" {
		t.Errorf("full-tunnel path = %q", got)
	}
	if got := ConnectIPPath("*", "*"); got != "/.well-known/masque/ip/*/*/" {
		t.Errorf("explicit path = %q", got)
	}
}

func TestIsConnectIP(t *testing.T) {
	if !IsConnectIP(ConnectIPHeaders("proxy.example", "/.well-known/masque/ip/*/*/")) {
		t.Error("a well-formed CONNECT-IP request was not recognised")
	}
	if IsConnectIP([]http3.Field{{Name: ":method", Value: "GET"}, {Name: ":protocol", Value: "connect-ip"}}) {
		t.Error("a GET was accepted as CONNECT-IP")
	}
}
