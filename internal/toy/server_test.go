package toy

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
)

// newTestServer builds a server on a real loopback socket with no TUN.
//
// A nil TUN is fine here because these tests stop at the handshake: nothing
// reaches the data path, which is the only thing that would touch it.
func newTestServer(t *testing.T, poolCIDR string) (*Server, *net.UDPAddr) {
	t.Helper()

	pool, _, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		t.Fatalf("building pool: %v", err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv, err := NewServer(conn, nil, ServerConfig{
		Users: map[string]string{"alice": "s3cret"},
		Pool:  pool,
		MTU:   1400,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, conn.LocalAddr().(*net.UDPAddr)
}

func helloFor(nonce [NonceLen]byte, user string) []byte {
	out := AppendHeader(nil, Header{Type: MsgHello, Counter: 1})
	return AppendHello(out, Hello{Nonce: nonce, User: user})
}

// A HELLO is retransmitted whenever the CHALLENGE is lost, so handling one must
// be idempotent. Allocating per HELLO would let a lossy link burn a pool address
// per retransmission, and a peer that simply repeated the message could exhaust
// the pool outright.
func TestRepeatedHelloReusesOneSession(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/24")
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

	var nonce [NonceLen]byte
	copy(nonce[:], "retryyy")
	hello := helloFor(nonce, "alice")

	for range 10 {
		h, body, err := ParseHeader(hello)
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		if h.Type != MsgHello {
			t.Fatalf("type = %v, want HELLO", h.Type)
		}
		srv.handleHello(body, from)
	}

	srv.mu.Lock()
	pendingCount := len(srv.pending)
	srv.mu.Unlock()

	if pendingCount != 1 {
		t.Errorf("ten retransmissions of one HELLO produced %d handshakes, want 1", pendingCount)
	}
}

// A genuinely different client must still get its own session, or the dedupe
// would collapse distinct peers onto one.
func TestDistinctHellosGetDistinctSessions(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/24")

	for i := range 3 {
		var nonce [NonceLen]byte
		nonce[0] = byte(i)
		from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000 + i}

		_, body, err := ParseHeader(helloFor(nonce, "alice"))
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		srv.handleHello(body, from)
	}

	srv.mu.Lock()
	pendingCount := len(srv.pending)
	srv.mu.Unlock()

	if pendingCount != 3 {
		t.Errorf("three distinct clients produced %d handshakes, want 3", pendingCount)
	}
}

func TestUnknownUserRejected(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/24")
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

	var nonce [NonceLen]byte
	_, body, err := ParseHeader(helloFor(nonce, "mallory"))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	srv.handleHello(body, from)

	srv.mu.Lock()
	pendingCount := len(srv.pending)
	srv.mu.Unlock()

	if pendingCount != 0 {
		t.Errorf("an unknown user started %d handshakes, want 0", pendingCount)
	}
}

// A bad proof must release the address the handshake reserved, or a peer that
// authenticates incorrectly repeatedly would drain the pool.
func TestFailedAuthReleasesTheAddress(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/30") // room for very few clients
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

	for i := range 8 {
		var nonce [NonceLen]byte
		nonce[0] = byte(i)

		_, body, err := ParseHeader(helloFor(nonce, "alice"))
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		srv.handleHello(body, from)

		srv.mu.Lock()
		var id uint16
		for sid := range srv.pending {
			id = sid
			break
		}
		srv.mu.Unlock()
		if id == 0 {
			t.Fatalf("attempt %d: the pool was exhausted by failed authentications", i)
		}

		// Answer with a proof that cannot verify.
		bad := make([]byte, TagLen)
		srv.handleAuth(Header{Type: MsgAuth, Session: id, Counter: 2}, bad, from)
	}

	srv.mu.Lock()
	sessions, pendingCount := len(srv.sessions), len(srv.pending)
	srv.mu.Unlock()
	if sessions != 0 || pendingCount != 0 {
		t.Errorf("after eight failed authentications: %d sessions, %d pending; want 0, 0",
			sessions, pendingCount)
	}
}

func TestSessionIDIsNeverZero(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/24")
	for range 50 {
		id, err := srv.newSessionID()
		if err != nil {
			t.Fatalf("newSessionID: %v", err)
		}
		if id == 0 {
			t.Fatal("allocated session 0, which is reserved for \"not yet assigned\"")
		}
	}
}
