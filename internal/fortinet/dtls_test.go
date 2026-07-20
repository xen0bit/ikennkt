package fortinet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

// selfSignedECDSA builds a certificate valid for 127.0.0.1, plus a pool that
// trusts it -- the same trust the HTTPS login and the DTLS channel share.
func selfSignedECDSA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-fortinet-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dtlsTestServer starts a Fortinet server whose HTTPS control plane and UDP data
// channel share one certificate, and returns it with the client's trust pool.
func dtlsTestServer(t *testing.T, srv *Server, cert tls.Certificate) (base string, udpAddr *net.UDPAddr) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serve, err := srv.EnableDTLS(udp)
	if err != nil {
		t.Fatal(err)
	}
	go serve()

	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL, udp.LocalAddr().(*net.UDPAddr)
}

// The whole Fortinet stack over the UDP data channel: HTTPS login, a config that
// advertises DTLS, the certificate-based DTLS handshake, the GFtype cookie
// exchange, PPP, and an IP packet each way.
func TestDTLSEndToEnd(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		DNS:         []net.IP{net.IPv4(1, 1, 1, 1)},
		Certificate: &cert,
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	go srv.RunTUN()
	defer srv.Close()

	base, udpAddr := dtlsTestServer(t, srv, cert)

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}
	cfg, cookie, err := Login(hc, base, "alice", "s3cret", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !cfg.DTLS {
		t.Fatal("server with a DTLS channel did not advertise dtls=1")
	}
	clientIP := cfg.AssignedIP

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DialDTLS(udp, cookie, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("DialDTLS: %v", err)
	}

	clientTUN := newFakeTUN()
	client, err := RunDTLSClient(dc, cfg, clientTUN, nil)
	if err != nil {
		t.Fatalf("RunDTLSClient: %v", err)
	}
	defer client.Close()

	clientTUN.inbound <- ipv4(clientIP, gateway, "ping")
	select {
	case got := <-serverTUN.outbound:
		if string(got[20:]) != "ping" {
			t.Errorf("server TUN payload = %q, want ping", got[20:])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet did not reach the server TUN over DTLS")
	}

	serverTUN.inbound <- ipv4(gateway, clientIP, "pong")
	select {
	case got := <-clientTUN.outbound:
		if string(got[20:]) != "pong" {
			t.Errorf("client TUN payload = %q, want pong", got[20:])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet did not reach the client TUN over DTLS")
	}
}

// A DTLS session that presents a cookie the login never issued must be refused:
// the certificate proves the server, not the client, so the cookie is the only
// thing standing between a stranger's handshake and a PPP link.
func TestDTLSRejectsUnknownCookie(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_, udpAddr := dtlsTestServer(t, srv, cert)

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialDTLS(udp, "not-a-cookie", &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}); err == nil {
		t.Fatal("DialDTLS succeeded with a cookie the server never issued")
	}
	if n := srv.Clients(); n != 0 {
		t.Errorf("server has %d links after a rejected session, want 0", n)
	}
}

// A client that will not trust the gateway's certificate must not get a session:
// the DTLS channel is not a weaker second door into the same server.
func TestDTLSRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := selfSignedECDSA(t)
	_, otherRoots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_, udpAddr := dtlsTestServer(t, srv, cert)

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialDTLS(udp, "cookie", &tls.Config{RootCAs: otherRoots, ServerName: "127.0.0.1"}); err == nil {
		t.Fatal("DialDTLS accepted a certificate signed by an untrusted CA")
	}
}

// EnableDTLS must refuse a server that has no certificate rather than bind a
// socket that could never complete a handshake.
func TestEnableDTLSRequiresCertificate(t *testing.T) {
	pool, gateway, _ := newTestPool()
	srv, err := NewServer(ServerConfig{
		Users: map[string]string{"alice": "s3cret"}, Pool: pool, ServerIP: gateway,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err := srv.EnableDTLS(udp); err == nil {
		t.Fatal("EnableDTLS bound a channel with no certificate")
	}
}
