package dataplane

import "net/netip"

// routeTable maps an inner IP destination to the tunnel that carries it, by
// longest-prefix match. Both address families are held side by side: a v4 trie
// (32 bits) and a v6 trie (128 bits), selected per lookup by the address family,
// so a dual-stack tunnel can own both a v4 and a v6 prefix.
//
// A single-host route would do for IKEv2, where every client owns exactly one
// assigned address per family, but WireGuard's cryptokey routing gives each peer
// a set of prefixes (AllowedIPs) and picks the most specific match. Both fit
// here: a /32 or /128 is just a full-length prefix, and a client's "everything
// goes to the server" is 0.0.0.0/0 or ::/0.
//
// Each trie is an uncompressed binary trie over its address bits. Depth is
// bounded by the prefix length, so the common shapes are cheap: a lone default
// route resolves at the root, and the walk stops as soon as it runs out of
// children.
type routeTable struct {
	root4 *routeNode
	root6 *routeNode
}

type routeNode struct {
	child [2]*routeNode
	val   Tunnel
	set   bool
}

// rootFor returns the address of the trie root for a's family (create allocates
// it on demand). The returned **routeNode lets insert grow an empty trie.
func (t *routeTable) rootFor(a netip.Addr, create bool) **routeNode {
	root := &t.root6
	if a.Is4() {
		root = &t.root4
	}
	if *root == nil && create {
		*root = &routeNode{}
	}
	return root
}

// insert adds or replaces the tunnel for p. The prefix's family selects the trie.
func (t *routeTable) insert(p netip.Prefix, v Tunnel) {
	p = p.Masked()
	root := t.rootFor(p.Addr(), true)
	n := *root
	for i := 0; i < p.Bits(); i++ {
		b := addrBit(p.Addr(), i)
		if n.child[b] == nil {
			n.child[b] = &routeNode{}
		}
		n = n.child[b]
	}
	n.val, n.set = v, true
}

// remove drops p's entry. Interior nodes are left in place: route sets are small
// and churn with SA lifetime, not per packet, so pruning would buy nothing.
func (t *routeTable) remove(p netip.Prefix) {
	if n := t.node(p); n != nil {
		n.val, n.set = nil, false
	}
}

// removeOwned drops p's entry only while owner still holds it.
//
// Make-before-break SA replacement — install the new tunnel, then retire the old
// — has both tunnels claiming the same prefix, and insert has already handed it
// to the new one. An unconditional remove on the way past would tear out the
// live route and black-hole every outbound packet from then on.
func (t *routeTable) removeOwned(p netip.Prefix, owner Tunnel) {
	if n := t.node(p); n != nil && n.set && n.val == owner {
		n.val, n.set = nil, false
	}
}

// node walks to p's node, or nil when the trie has no branch that far.
func (t *routeTable) node(p netip.Prefix) *routeNode {
	p = p.Masked()
	n := *t.rootFor(p.Addr(), false)
	if n == nil {
		return nil
	}
	for i := 0; i < p.Bits(); i++ {
		b := addrBit(p.Addr(), i)
		if n.child[b] == nil {
			return nil
		}
		n = n.child[b]
	}
	return n
}

// lookup returns the tunnel whose prefix matches a most specifically, or nil.
// The address family selects the trie; the walk length is the family's bit width.
func (t *routeTable) lookup(a netip.Addr) Tunnel {
	n := *t.rootFor(a, false)
	bits := a.BitLen() // 32 for v4, 128 for v6
	var best Tunnel
	for i := 0; n != nil; i++ {
		if n.set {
			best = n.val
		}
		if i == bits {
			break
		}
		n = n.child[addrBit(a, i)]
	}
	return best
}

// empty reports whether any route is installed in either family.
func (t *routeTable) empty() bool { return t.root4 == nil && t.root6 == nil }

// addrBit returns bit i of a (0 = most significant), reading the 4-byte form for
// IPv4 and the 16-byte form for IPv6.
func addrBit(a netip.Addr, i int) uint8 {
	if a.Is4() {
		b := a.As4()
		return (b[i>>3] >> (7 - uint(i&7))) & 1
	}
	b := a.As16()
	return (b[i>>3] >> (7 - uint(i&7))) & 1
}
