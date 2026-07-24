package payload

import (
	"bytes"
	"testing"
)

func TestCertPayloadRoundTrip(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef} // stand-in DER
	body := MarshalCert(CertPayload{Encoding: CertX509Signature, Data: der})
	got, err := ParseCert(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Encoding != CertX509Signature {
		t.Errorf("encoding = %d, want %d", got.Encoding, CertX509Signature)
	}
	if !bytes.Equal(got.Data, der) {
		t.Errorf("cert data mismatch: got %x", got.Data)
	}
}

func TestCertReqPayloadRoundTrip(t *testing.T) {
	// Two 20-octet CA key hashes concatenated.
	cas := bytes.Repeat([]byte{0xab}, 20)
	cas = append(cas, bytes.Repeat([]byte{0xcd}, 20)...)
	body := MarshalCertReq(CertReqPayload{Encoding: CertX509Signature, CAs: cas})
	got, err := ParseCertReq(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Encoding != CertX509Signature {
		t.Errorf("encoding = %d, want %d", got.Encoding, CertX509Signature)
	}
	if !bytes.Equal(got.CAs, cas) {
		t.Errorf("CA field mismatch: got %x", got.CAs)
	}
}

// An empty CERTREQ CA field ("any trusted CA") must survive the round trip as a
// zero-length, non-nil slice.
func TestCertReqEmptyCAs(t *testing.T) {
	body := MarshalCertReq(CertReqPayload{Encoding: CertX509Signature})
	got, err := ParseCertReq(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CAs) != 0 {
		t.Errorf("expected empty CA field, got %x", got.CAs)
	}
}

func TestParseCertTruncated(t *testing.T) {
	if _, err := ParseCert(nil); err == nil {
		t.Error("ParseCert(nil) should fail")
	}
	if _, err := ParseCertReq(nil); err == nil {
		t.Error("ParseCertReq(nil) should fail")
	}
}
