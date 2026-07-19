package http3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"golang.org/x/net/quic"
)

// loopbackQUIC returns a connected client/server *quic.Conn pair over the real
// QUIC stack on the loopback interface. It is the honest substrate for these
// tests: a mock stream would not exercise the framing against x/net/quic's
// actual flow control and stream lifecycle, which is where an HTTP/3 layer
// tends to be wrong.
func loopbackQUIC(t *testing.T) (clientConn, serverConn *quic.Conn) {
	t.Helper()
	ctx := context.Background()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	cliTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}

	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srvEnd.Close(ctx) })

	cliEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: cliTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cliEnd.Close(ctx) })

	accepted := make(chan *quic.Conn, 1)
	go func() {
		c, err := srvEnd.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	clientConn, err = cliEnd.Dial(ctx, "udp", srvEnd.LocalAddr().String(), &quic.Config{TLSConfig: cliTLS})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case serverConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept the QUIC connection")
	}
	return clientConn, serverConn
}

// The whole Phase 0 substrate in one exchange: SETTINGS both ways, an Extended
// CONNECT with a :status 200 response, and a capsule byte round-trip over the
// DATA-frame transport.
func TestConnectRoundTrip(t *testing.T) {
	ctx := context.Background()
	cliQ, srvQ := loopbackQUIC(t)

	srv, err := Server(ctx, srvQ)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := Client(ctx, cliQ)
	if err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		rs, fields, err := srv.AcceptConnect(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if get(fields, ":method") != "CONNECT" || get(fields, ":protocol") != "connect-ip" {
			serverDone <- fmt.Errorf("unexpected request headers: %v", fields)
			return
		}
		if err := rs.WriteResponse([]Field{{":status", "200"}, {"capsule-protocol", "?1"}}); err != nil {
			serverDone <- err
			return
		}
		// Echo one capsule-stream message.
		buf := make([]byte, 64)
		n, err := rs.Read(buf)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = rs.Write(buf[:n])
		serverDone <- err
	}()

	rs, err := cli.OpenConnect(ctx, []Field{
		{":method", "CONNECT"},
		{":scheme", "https"},
		{":authority", "proxy.example"},
		{":path", "/.well-known/masque/ip/*/*/"},
		{":protocol", "connect-ip"},
		{"capsule-protocol", "?1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if get(resp, ":status") != "200" {
		t.Fatalf("status = %q, want 200", get(resp, ":status"))
	}

	msg := []byte("capsule payload")
	if _, err := rs.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	n, err := rs.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(msg) {
		t.Errorf("echo = %q, want %q", got[:n], msg)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// A client must refuse to send Extended CONNECT to a server that does not
// advertise ENABLE_CONNECT_PROTOCOL. This is enforced by OpenConnect, so the
// mistake cannot reach the wire.
func TestConnectRequiresServerOptIn(t *testing.T) {
	ctx := context.Background()
	cliQ, srvQ := loopbackQUIC(t)

	// A bare server that sends SETTINGS without ENABLE_CONNECT_PROTOCOL.
	ctrl, err := srvQ.NewSendOnlyStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ctrl.Write(AppendVarint(nil, StreamControl))
	_ = WriteFrame(ctrl, FrameSettings, Settings{SettingQPACKMaxTableCapacity: 0}.Encode())
	_ = ctrl.Flush()

	cli, err := Client(ctx, cliQ)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.OpenConnect(ctx, []Field{{":method", "CONNECT"}})
	if err != ErrNoConnectProtocol {
		t.Fatalf("OpenConnect error = %v, want ErrNoConnectProtocol", err)
	}
}

func get(fields []Field, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}
