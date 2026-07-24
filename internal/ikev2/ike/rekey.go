package ike

import (
	"context"
	"fmt"
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// Child SA rekey (RFC 7296 section 2.8). An ESP SA has a finite lifetime — a
// byte ceiling and a wall-clock soft lifetime — after which its keys must be
// replaced or the tunnel stops. Rekeying does this without dropping traffic: the
// initiator runs a CREATE_CHILD_SA exchange to negotiate a fresh SA (new SPIs,
// new keys derived from fresh nonces), the data path is swapped onto it, and the
// old SA is deleted. It reuses the post-handshake control channel (Attach) and
// serializes with DPD and MOBIKE roam via exchMu.
//
// The initiator side lives here; the responder's CREATE_CHILD_SA and Delete
// handling is in child_info.go.

// RekeyChild negotiates a replacement Child SA and returns the new parameters as
// a ClientResult (so the caller can BuildTunnel it) together with the inbound
// SPI of the SA being replaced, which the caller retires once the swap is live.
// It updates the client's own notion of the current Child SA on success.
//
// It requires Attach (post-handshake control mode); the exchange reads its
// response from the delivered inbox, not the socket.
func (c *Client) RekeyChild(ctx context.Context) (newRes *ClientResult, oldInSPI uint32, err error) {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return nil, 0, errNotAttached
	}
	if c.result == nil {
		return nil, 0, fmt.Errorf("ike: no Child SA to rekey")
	}
	oldInSPI = c.result.InboundSPI
	oldOutSPI := c.result.OutboundSPI

	newInSPI := newChildSPI()
	ni := mustNonce(32)
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}

	b := payload.NewBuilder()
	// REKEY_SA identifies the SA being replaced (RFC 7296 2.8): its SPI is the one
	// the peer sends to — i.e. our old outbound SPI (the peer's inbound). This is
	// what lets a compliant responder (strongSwan) delete the old SA rather than
	// treat this as an unrelated new child.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoESP, Type: payload.RekeySA, SPI: u32BE(oldOutSPI),
	}))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{DefaultESPProposal(u32BE(newInSPI))},
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(ni))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))

	msgID := c.sendMsgID
	pkt, err := c.seal(payload.CREATE_CHILD_SA, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return nil, 0, err
	}
	if err := c.writeIKE(pkt); err != nil {
		return nil, 0, fmt.Errorf("ike: rekey send: %w", err)
	}
	inners, err := c.recvInnersFrom(c.recvControl(ctx))
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response: %w", err)
	}

	saPay := findInner(inners, payload.TypeSA)
	noncePay := findInner(inners, payload.TypeNonce)
	if saPay == nil || noncePay == nil {
		return nil, 0, fmt.Errorf("ike: rekey response missing SA/Nonce")
	}
	espSA, err := payload.ParseSA(saPay.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response SA: %w", err)
	}
	es, _, err := SelectESPSuite(espSA)
	if err != nil {
		return nil, 0, fmt.Errorf("ike: rekey response suite: %w", err)
	}
	nr := payload.ParseNonce(noncePay.Body)

	var newOutSPI uint32
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		newOutSPI = beU32(espSA.Proposals[0].SPI)
	}
	if newOutSPI == 0 {
		return nil, 0, fmt.Errorf("ike: rekey response carried no SPI")
	}

	// Derive the new Child keys exactly as the initial handshake does: KEYMAT
	// from SK_d over Ni|Nr of *this* exchange, split enc_i|integ_i|enc_r|integ_r.
	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	km := DeriveChildKeys(c.suite.PRF, c.keys.SKd, nil, ni, nr, 2*encLen+2*integLen)
	off := 0
	take := func(n int) []byte { v := km[off : off+n]; off += n; return v }

	// Copy the stable fields (assigned address, server endpoint, suite) and
	// replace the SPIs and keys.
	res := *c.result
	res.InboundSPI = newInSPI
	res.OutboundSPI = newOutSPI
	res.Suite = es
	res.EncKeyOut = take(encLen)
	if integLen > 0 {
		res.IntegKeyOut = take(integLen)
	} else {
		res.IntegKeyOut = nil
	}
	res.EncKeyIn = take(encLen)
	if integLen > 0 {
		res.IntegKeyIn = take(integLen)
	} else {
		res.IntegKeyIn = nil
	}

	c.sendMsgID = msgID + 1
	c.result = &res
	return &res, oldInSPI, nil
}

// DeleteChildSA tears down a Child SA by its inbound SPI with a protected
// INFORMATIONAL Delete (RFC 7296 1.4.1). Called after a rekey swap has moved
// traffic to the replacement SA, so the old one can be retired.
func (c *Client) DeleteChildSA(ctx context.Context, inSPI uint32) error {
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	if !c.attached.Load() {
		return errNotAttached
	}
	b := payload.NewBuilder()
	b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{
		Protocol: payload.ProtoESP, SPISize: 4, SPIs: [][]byte{u32BE(inSPI)},
	}))
	msgID := c.sendMsgID
	pkt, err := c.seal(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKE(pkt); err != nil {
		return fmt.Errorf("ike: delete send: %w", err)
	}
	if _, err := c.recvInnersFrom(c.recvControl(ctx)); err != nil {
		return fmt.Errorf("ike: delete response: %w", err)
	}
	c.sendMsgID = msgID + 1
	return nil
}

// CurrentServerAddr returns the address ESP is currently sent to, so a rekeyed
// tunnel inherits the peer endpoint (which MOBIKE roam may have moved).
func (c *Client) CurrentServerAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.result != nil && c.result.ServerAddr != nil {
		return c.result.ServerAddr
	}
	return c.conn.RemoteAddr().(*net.UDPAddr)
}
