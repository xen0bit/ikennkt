package noise

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// testResponder is the mirror of Initiator, written from the protocol paper
// §5.4.2/§5.4.3 responder pseudocode.
//
// It exists to check the initiator's KDF ordering, hash mixing, AEAD AAD and key
// directions without a network. It deliberately proves less than it looks like it
// does: both sides share this package's constants, so a misread constant would
// pass here and fail against a real peer. That is what the Docker interop test
// against a real wg is for; this one localizes the failure when interop breaks.
type testResponder struct {
	static   *ecdh.PrivateKey
	psk      [KeySize]byte
	ck, h    key
	eph      *ecdh.PrivateKey
	peerEph  *ecdh.PublicKey
	peerIdx  uint32
	localIdx uint32
}

// consumeInitiation is the paper's §5.4.2 read from the responder's side.
func (r *testResponder) consumeInitiation(t *testing.T, pkt []byte) {
	t.Helper()
	msg, err := wire.ParseHandshakeInitiation(pkt)
	if err != nil {
		t.Fatal(err)
	}
	r.peerIdx = msg.Sender

	r.ck = hashOf([]byte(construction))
	ih := hashOf(r.ck[:], []byte(identifier))
	r.h = hashOf(ih[:], r.static.PublicKey().Bytes())

	peerEph, err := ecdh.X25519().NewPublicKey(msg.Ephemeral[:])
	if err != nil {
		t.Fatal(err)
	}
	r.peerEph = peerEph

	r.h = hashOf(r.h[:], msg.Ephemeral[:])
	r.ck = kdf1(&r.ck, msg.Ephemeral[:])

	// DH(responder.static_private, initiator.ephemeral_public) mirrors the
	// initiator's DH(ephemeral_private, responder.static_public).
	es, err := r.static.ECDH(peerEph)
	if err != nil {
		t.Fatal(err)
	}
	ck, k := kdf2(&r.ck, es)
	r.ck = ck

	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		t.Fatal(err)
	}
	peerStaticBytes, err := aead.Open(nil, zeroNonce[:], msg.Static[:], r.h[:])
	if err != nil {
		t.Fatalf("responder could not open encrypted_static: %v", err)
	}
	peerStatic, err := ecdh.X25519().NewPublicKey(peerStaticBytes)
	if err != nil {
		t.Fatal(err)
	}
	r.h = hashOf(r.h[:], msg.Static[:])

	ss, err := r.static.ECDH(peerStatic)
	if err != nil {
		t.Fatal(err)
	}
	ck, k = kdf2(&r.ck, ss)
	r.ck = ck

	aead, err = cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aead.Open(nil, zeroNonce[:], msg.Timestamp[:], r.h[:]); err != nil {
		t.Fatalf("responder could not open encrypted_timestamp: %v", err)
	}
	r.h = hashOf(r.h[:], msg.Timestamp[:])

	// mac1 must match what the responder expects for its own static key.
	over1, _, ok := wire.MACRegions(pkt)
	if !ok {
		t.Fatal("no MAC regions")
	}
	mac1Key := hashOf([]byte(labelMAC1), r.static.PublicKey().Bytes())
	want := mac128(mac1Key[:], over1)
	if !bytes.Equal(want[:], msg.MAC1[:]) {
		t.Fatal("mac1 does not authenticate the initiation to the responder's key")
	}
	if msg.MAC2 != ([wire.MACSize]byte{}) {
		t.Fatal("mac2 should be zero without a cookie")
	}
}

// response is the paper's §5.4.3 from the responder's side.
func (r *testResponder) response(t *testing.T) ([]byte, Keypair) {
	t.Helper()
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.eph = eph
	r.localIdx = 0xfeedface

	msg := &wire.HandshakeResponse{Sender: r.localIdx, Receiver: r.peerIdx}
	copy(msg.Ephemeral[:], eph.PublicKey().Bytes())

	r.h = hashOf(r.h[:], msg.Ephemeral[:])
	r.ck = kdf1(&r.ck, msg.Ephemeral[:])

	ee, err := eph.ECDH(r.peerEph)
	if err != nil {
		t.Fatal(err)
	}
	r.ck = kdf1(&r.ck, ee)

	// DH(responder.ephemeral_private, initiator.static_public): the initiator
	// computes the same value as DH(static_private, responder.ephemeral_public).
	peerStatic, err := r.recoverPeerStatic(t)
	if err != nil {
		t.Fatal(err)
	}
	se, err := eph.ECDH(peerStatic)
	if err != nil {
		t.Fatal(err)
	}
	r.ck = kdf1(&r.ck, se)

	ck, tau, k := kdf3(&r.ck, r.psk[:])
	r.ck = ck
	r.h = hashOf(r.h[:], tau[:])

	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		t.Fatal(err)
	}
	empty := aead.Seal(nil, zeroNonce[:], nil, r.h[:])
	copy(msg.Empty[:], empty)
	r.h = hashOf(r.h[:], msg.Empty[:])

	buf := make([]byte, wire.SizeHandshakeResponse)
	out, err := msg.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}

	// The responder's sending key is the initiator's receiving key, so the pair
	// is swapped relative to the initiator's.
	recv, send := kdf2(&r.ck, nil)
	return out, Keypair{Send: send, Recv: recv, Local: r.localIdx, Remote: r.peerIdx}
}

// peerStaticPub is stashed by the test so the responder need not re-derive it.
var peerStaticPub *ecdh.PublicKey

func (r *testResponder) recoverPeerStatic(t *testing.T) (*ecdh.PublicKey, error) {
	t.Helper()
	return peerStaticPub, nil
}

func genKey(t *testing.T) ([KeySize]byte, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b [KeySize]byte
	copy(b[:], priv.Bytes())
	return b, priv
}

// TestHandshakeAgreesOnTransportKeys is the core property: after a full
// exchange, the initiator's sending key is the responder's receiving key and
// vice versa. Any misordered KDF step, missing hash mix or swapped direction
// breaks it.
func TestHandshakeAgreesOnTransportKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		psk  [KeySize]byte
	}{
		{"without psk", [KeySize]byte{}},
		{"with psk", [KeySize]byte{1, 2, 3, 4, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initStatic, initPriv := genKey(t)
			respStatic, respPriv := genKey(t)
			peerStaticPub = initPriv.PublicKey()

			var respPub [KeySize]byte
			copy(respPub[:], respPriv.PublicKey().Bytes())

			i, err := NewInitiator(Config{
				LocalStatic:  initStatic,
				RemoteStatic: respPub,
				PresharedKey: tc.psk,
			})
			if err != nil {
				t.Fatal(err)
			}
			_ = respStatic

			initPkt, err := i.Initiation()
			if err != nil {
				t.Fatal(err)
			}
			if len(initPkt) != wire.SizeHandshakeInitiation {
				t.Fatalf("initiation is %d octets, want %d", len(initPkt), wire.SizeHandshakeInitiation)
			}

			r := &testResponder{static: respPriv, psk: tc.psk}
			r.consumeInitiation(t, initPkt)
			respPkt, rKeys := r.response(t)

			iKeys, err := i.Consume(respPkt)
			if err != nil {
				t.Fatalf("initiator could not consume the response: %v", err)
			}

			if iKeys.Send != rKeys.Recv {
				t.Error("initiator's sending key is not the responder's receiving key")
			}
			if iKeys.Recv != rKeys.Send {
				t.Error("initiator's receiving key is not the responder's sending key")
			}
			if iKeys.Send == iKeys.Recv {
				t.Error("sending and receiving keys are identical")
			}
			if iKeys.Local != i.LocalIndex() || iKeys.Remote != r.localIdx {
				t.Errorf("indices: local %#x remote %#x, want %#x/%#x",
					iKeys.Local, iKeys.Remote, i.LocalIndex(), r.localIdx)
			}
		})
	}
}

// TestHandshakeRejectsWrongPSK checks the preshared key is actually bound in:
// with a mismatched PSK the response must fail to authenticate.
func TestHandshakeRejectsWrongPSK(t *testing.T) {
	initStatic, initPriv := genKey(t)
	_, respPriv := genKey(t)
	peerStaticPub = initPriv.PublicKey()

	var respPub [KeySize]byte
	copy(respPub[:], respPriv.PublicKey().Bytes())

	i, err := NewInitiator(Config{
		LocalStatic:  initStatic,
		RemoteStatic: respPub,
		PresharedKey: [KeySize]byte{0xaa},
	})
	if err != nil {
		t.Fatal(err)
	}
	initPkt, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}

	// The responder uses a different PSK.
	r := &testResponder{static: respPriv, psk: [KeySize]byte{0xbb}}
	r.consumeInitiation(t, initPkt)
	respPkt, _ := r.response(t)

	if _, err := i.Consume(respPkt); err != ErrDecrypt {
		t.Fatalf("wrong PSK gave %v, want ErrDecrypt", err)
	}
}

// TestConsumeRejectsWrongReceiver ensures a response for another session is not
// processed, which is what stops one peer's response from disturbing another's
// handshake.
func TestConsumeRejectsWrongReceiver(t *testing.T) {
	initStatic, initPriv := genKey(t)
	_, respPriv := genKey(t)
	peerStaticPub = initPriv.PublicKey()
	var respPub [KeySize]byte
	copy(respPub[:], respPriv.PublicKey().Bytes())

	i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
	if err != nil {
		t.Fatal(err)
	}
	initPkt, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	r := &testResponder{static: respPriv}
	r.consumeInitiation(t, initPkt)
	respPkt, _ := r.response(t)

	// Corrupt the receiver index.
	respPkt[8] ^= 0xff
	if _, err := i.Consume(respPkt); err != ErrWrongReceiver {
		t.Fatalf("mismatched receiver gave %v, want ErrWrongReceiver", err)
	}
}

// TestInitiationIsSingleUse guards ephemeral reuse: a second Initiation from the
// same Initiator must be refused rather than silently reuse the ephemeral key.
func TestInitiationIsSingleUse(t *testing.T) {
	initStatic, _ := genKey(t)
	_, respPriv := genKey(t)
	var respPub [KeySize]byte
	copy(respPub[:], respPriv.PublicKey().Bytes())

	i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Initiation(); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Initiation(); err == nil {
		t.Fatal("a second Initiation was allowed; the ephemeral would be reused")
	}
}

// TestConsumeBeforeInitiation rejects an out-of-order response.
func TestConsumeBeforeInitiation(t *testing.T) {
	initStatic, _ := genKey(t)
	_, respPriv := genKey(t)
	var respPub [KeySize]byte
	copy(respPub[:], respPriv.PublicKey().Bytes())

	i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Consume(make([]byte, wire.SizeHandshakeResponse)); err == nil {
		t.Fatal("a response before the initiation was accepted")
	}
}

// TestEachHandshakeUsesAFreshEphemeral checks two Initiators to the same peer
// produce different ephemerals and session indices.
func TestEachHandshakeUsesAFreshEphemeral(t *testing.T) {
	initStatic, _ := genKey(t)
	_, respPriv := genKey(t)
	var respPub [KeySize]byte
	copy(respPub[:], respPriv.PublicKey().Bytes())

	mk := func() ([]byte, uint32) {
		i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := i.Initiation()
		if err != nil {
			t.Fatal(err)
		}
		return pkt[8:40], i.LocalIndex()
	}
	e1, i1 := mk()
	e2, i2 := mk()
	if bytes.Equal(e1, e2) {
		t.Error("two handshakes reused the same ephemeral public key")
	}
	if i1 == i2 {
		t.Error("two handshakes reused the same session index")
	}
}

func TestPublicKeyMatchesECDH(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b [KeySize]byte
	copy(b[:], priv.Bytes())
	got, err := PublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], priv.PublicKey().Bytes()) {
		t.Fatal("PublicKey disagrees with crypto/ecdh")
	}
}
