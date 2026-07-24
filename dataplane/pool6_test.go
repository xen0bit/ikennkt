package dataplane

import (
	"net/netip"
	"testing"
)

func TestAddrPool6AllocateReleaseReuse(t *testing.T) {
	p, gw, err := NewAddrPool6("fd00:10:10::/64")
	if err != nil {
		t.Fatalf("NewAddrPool6: %v", err)
	}
	if want := netip.MustParseAddr("fd00:10:10::1"); gw != want {
		t.Fatalf("gateway = %s, want %s", gw, want)
	}
	if p.Bits() != 64 {
		t.Fatalf("Bits = %d, want 64", p.Bits())
	}

	// First two allocations skip the network (::0) and gateway (::1).
	a1, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if want := netip.MustParseAddr("fd00:10:10::2"); a1 != want {
		t.Fatalf("first alloc = %s, want %s", a1, want)
	}
	a2, _ := p.Allocate()
	if want := netip.MustParseAddr("fd00:10:10::3"); a2 != want {
		t.Fatalf("second alloc = %s, want %s", a2, want)
	}
	if !p.Prefix().Contains(a1) {
		t.Fatalf("allocated address %s outside prefix", a1)
	}

	// Releasing a1 makes it the next handed out again (compact reuse).
	p.Release(a1)
	a3, _ := p.Allocate()
	if a3 != a1 {
		t.Fatalf("after release, alloc = %s, want reused %s", a3, a1)
	}

	// Releasing an address never allocated is a no-op.
	p.Release(netip.MustParseAddr("fd00:10:10::dead"))
}

func TestAddrPool6Exhaustion(t *testing.T) {
	// /126 leaves ::0 (network), ::1 (gateway), ::2, ::3 — two client hosts.
	p, _, err := NewAddrPool6("fd00::/126")
	if err != nil {
		t.Fatalf("NewAddrPool6: %v", err)
	}
	if _, err := p.Allocate(); err != nil {
		t.Fatalf("first alloc: %v", err)
	}
	if _, err := p.Allocate(); err != nil {
		t.Fatalf("second alloc: %v", err)
	}
	if _, err := p.Allocate(); err == nil {
		t.Fatal("expected exhaustion error, got nil")
	}
}

func TestNewAddrPool6Rejects(t *testing.T) {
	for _, cidr := range []string{
		"10.10.10.0/24", // IPv4
		"fd00::/127",    // too small (one host)
		"not-a-prefix",  // malformed
	} {
		if _, _, err := NewAddrPool6(cidr); err == nil {
			t.Errorf("NewAddrPool6(%q) = nil error, want rejection", cidr)
		}
	}
}
