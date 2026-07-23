package ike

import (
	"bytes"
	"context"
	"io"
	"log"
	"testing"
	"time"
)

// TestClientRekeyChild is the rekey proof: a connected client negotiates a fresh
// Child SA, and the keys and SPIs it derives match the ones the server installs
// — so the new SA can actually carry traffic — while the old SA's SPI is handed
// back for retirement.
func TestClientRekeyChild(t *testing.T) {
	p500, p4500, srv, dp := mobikeServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("mobike-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	client.Attach()
	go pumpInbox(client)

	// Drain the Child SA the initial IKE_AUTH established.
	select {
	case <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no initial Child SA")
	}
	oldIn := res.InboundSPI

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	newRes, oldInSPI, err := client.RekeyChild(ctx)
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if oldInSPI != oldIn {
		t.Fatalf("rekey reported old inbound SPI %#x, want %#x", oldInSPI, oldIn)
	}
	if newRes.InboundSPI == oldIn {
		t.Fatal("rekey did not allocate a fresh inbound SPI")
	}

	// The server must have set up the replacement Child SA.
	var child *ChildSA
	select {
	case child = <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("server never installed the rekeyed Child SA")
	}

	// SPI agreement: the server's inbound is our outbound and vice versa.
	if child.InboundSPI != newRes.OutboundSPI {
		t.Fatalf("server inbound SPI %#x != our outbound %#x", child.InboundSPI, newRes.OutboundSPI)
	}
	if child.OutboundSPI != newRes.InboundSPI {
		t.Fatalf("server outbound SPI %#x != our inbound %#x", child.OutboundSPI, newRes.InboundSPI)
	}
	// Key agreement: the key the server opens inbound with is the one we seal
	// outbound with, and vice versa. This is what proves the rekeyed SA works.
	if !bytes.Equal(child.EncrIn, newRes.EncKeyOut) {
		t.Fatal("server inbound key != client outbound key after rekey")
	}
	if !bytes.Equal(child.EncrOut, newRes.EncKeyIn) {
		t.Fatal("server outbound key != client inbound key after rekey")
	}

	// The old SA can now be deleted cleanly.
	if err := client.DeleteChildSA(ctx, oldInSPI); err != nil {
		t.Fatalf("delete old Child SA: %v", err)
	}
}

// TestRekeyChildRequiresAttach confirms rekey refuses to run before the control
// channel is attached.
func TestRekeyChildRequiresAttach(t *testing.T) {
	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: 500,
		PSK:     []byte("x"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := client.RekeyChild(ctx); err == nil {
		t.Fatal("RekeyChild should fail before Attach")
	}
}
