package data

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// cbcPair builds a client and server CBCCipher with crossed keys, so packets one
// seals the other opens, for the given --auth digest.
func cbcPair(t *testing.T, newHash func() hash.Hash, size int) (client, server *CBCCipher) {
	t.Helper()
	var encKey, decKey [keys.GCMKeyLen]byte
	var encMAC, decMAC [64]byte
	for i := range encKey {
		encKey[i] = byte(i + 1)
		decKey[i] = byte(i + 100)
	}
	for i := range encMAC {
		encMAC[i] = byte(i + 3)
		decMAC[i] = byte(i + 200)
	}
	clientKeys := keys.CBCKeys{EncryptKey: encKey, DecryptKey: decKey, EncryptHMAC: encMAC, DecryptHMAC: decMAC}
	serverKeys := keys.CBCKeys{EncryptKey: decKey, DecryptKey: encKey, EncryptHMAC: decMAC, DecryptHMAC: encMAC}

	var err error
	client, err = NewCBC(clientKeys, newHash, size, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewCBC(serverKeys, newHash, size, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestCBCRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() hash.Hash
		size int
	}{
		{"SHA1", sha1.New, sha1.Size},
		{"SHA256", sha256.New, sha256.Size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := cbcPair(t, tc.new, tc.size)
			// Exercise several lengths, including a block-aligned one (full pad block)
			// and an empty payload.
			for _, n := range []int{0, 1, 15, 16, 28, 45, 1400} {
				msg := bytes.Repeat([]byte{byte(n)}, n)
				sealed, err := client.Seal(msg)
				if err != nil {
					t.Fatalf("seal %d: %v", n, err)
				}
				if sealed[0]>>opcodeShift != PDataV2 {
					t.Errorf("opcode = %d, want P_DATA_V2", sealed[0]>>opcodeShift)
				}
				got, err := server.Open(append([]byte(nil), sealed...))
				if err != nil {
					t.Fatalf("open %d: %v", n, err)
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("round trip %d = %x, want %x", n, got, msg)
				}
			}
		})
	}
}

func TestCBCPacketIDsIncrement(t *testing.T) {
	client, server := cbcPair(t, sha256.New, sha256.Size)
	for i := range 5 {
		sealed, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Open(append([]byte(nil), sealed...)); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	// A replay of the last packet is rejected.
	sealed, _ := client.Seal([]byte("x"))
	if _, err := server.Open(append([]byte(nil), sealed...)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(append([]byte(nil), sealed...)); err != errReplay {
		t.Errorf("replay: %v, want errReplay", err)
	}
}

func TestCBCRejectsTamper(t *testing.T) {
	client, server := cbcPair(t, sha256.New, sha256.Size)
	sealed, err := client.Seal([]byte("authentic data here, longer than a block"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a ciphertext bit: the HMAC must reject it before any decryption.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := server.Open(tampered); err != errAuth {
		t.Errorf("tampered ciphertext: %v, want errAuth", err)
	}
	// Flip an IV bit.
	tampered = append([]byte(nil), sealed...)
	tampered[headerLen+sha256.Size] ^= 0x01
	if _, err := server.Open(tampered); err != errAuth {
		t.Errorf("tampered IV: %v, want errAuth", err)
	}
}

func TestCBCPingRoundTrips(t *testing.T) {
	client, server := cbcPair(t, sha1.New, sha1.Size)
	sealed, err := client.Seal(Ping)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Open(append([]byte(nil), sealed...))
	if err != nil {
		t.Fatal(err)
	}
	if !IsPing(got) {
		t.Error("keepalive ping not recognised after CBC round trip")
	}
}

func TestCBCRejectsShort(t *testing.T) {
	_, server := cbcPair(t, sha256.New, sha256.Size)
	if _, err := server.Open(make([]byte, headerLen+sha256.Size)); err != errShort {
		t.Errorf("short packet: %v, want errShort", err)
	}
}

func TestPKCS7Unpad(t *testing.T) {
	// A full padding block.
	block := make([]byte, aes.BlockSize)
	for i := range block {
		block[i] = aes.BlockSize
	}
	out, err := pkcs7Unpad(block)
	if err != nil || len(out) != 0 {
		t.Errorf("full pad block: out=%x err=%v", out, err)
	}
	// A bad pad byte.
	block[len(block)-1] = 0
	if _, err := pkcs7Unpad(block); err != errShort {
		t.Errorf("zero pad: %v, want errShort", err)
	}
}
