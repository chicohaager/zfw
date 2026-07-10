//go:build linux

package conntrack

import (
	"encoding/binary"
	"os"
	"strings"
	"syscall"
	"testing"
)

// testdata/ctnetlink_dump.bin holds 40 real ctnetlink message bodies captured
// from a live ZimaOS 1.6.2 host (kernel 6.18.9) — the attribute layout is the
// kernel's own, not something this test invented. Only the IP addresses were
// rewritten in place (to 192.0.2.x / 2001:db8::x) so the fixture carries no
// private network topology; every length, offset and nesting is untouched.
//
// Format: a stream of uint32 little-endian length prefixes, each followed by
// that many bytes of message body (the attributes after nfgenmsg).
func loadFixture(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/ctnetlink_dump.bin")
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for len(raw) >= 4 {
		n := int(binary.LittleEndian.Uint32(raw[:4]))
		if n < 0 || 4+n > len(raw) {
			t.Fatalf("corrupt fixture: length %d exceeds remaining %d", n, len(raw)-4)
		}
		out = append(out, raw[4:4+n])
		raw = raw[4+n:]
	}
	if len(out) == 0 {
		t.Fatal("fixture is empty")
	}
	return out
}

// TestParseCTAgainstRealKernelDump is the regression guard for issue #1: the
// Connections tab was permanently empty on ZimaOS because neither
// /proc/net/nf_conntrack (CONFIG_NF_CONNTRACK_PROCFS is off) nor conntrack(8)
// exists there. Every record in this dump must decode.
func TestParseCTAgainstRealKernelDump(t *testing.T) {
	msgs := loadFixture(t)

	var tcp, udp, v6, withState int
	for i, body := range msgs {
		e, ok := parseCT(body)
		if !ok {
			t.Errorf("message %d: parseCT rejected a real kernel record", i)
			continue
		}
		if e.SrcIP == "" || e.DstIP == "" {
			t.Errorf("message %d: empty endpoint: %+v", i, e)
		}
		if e.Protocol == "" {
			t.Errorf("message %d: no protocol decoded: %+v", i, e)
		}
		if e.AgeSec <= 0 {
			t.Errorf("message %d: CTA_TIMEOUT not decoded (got %d)", i, e.AgeSec)
		}
		switch e.Protocol {
		case "tcp":
			tcp++
			if e.State != "" {
				withState++
			}
		case "udp":
			udp++
		}
		if strings.Contains(e.SrcIP, ":") {
			v6++
		}
	}
	if tcp == 0 || udp == 0 {
		t.Errorf("fixture lost coverage: tcp=%d udp=%d", tcp, udp)
	}
	if v6 == 0 {
		t.Error("fixture lost its IPv6 records — the v6 address attrs would go untested")
	}
	if withState == 0 {
		t.Error("no TCP record decoded a CTA_PROTOINFO_TCP_STATE")
	}
	t.Logf("decoded %d records: tcp=%d udp=%d ipv6=%d with-tcp-state=%d",
		len(msgs), tcp, udp, v6, withState)
}

// TestParseCTPortsAreBigEndian pins the classic ctnetlink bug: attribute
// headers are host byte order, payloads (ports, timeout) are network order.
// Reading a port little-endian turns 22 into 5632.
func TestParseCTPortsAreBigEndian(t *testing.T) {
	body := buildCT(t, 6, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, 22, 443, 300, 3)
	e, ok := parseCT(body)
	if !ok {
		t.Fatal("parseCT rejected a well-formed record")
	}
	if e.SrcPort != 22 || e.DstPort != 443 {
		t.Errorf("ports = %d->%d, want 22->443 (byte order swapped?)", e.SrcPort, e.DstPort)
	}
	if e.AgeSec != 300 {
		t.Errorf("AgeSec = %d, want 300", e.AgeSec)
	}
	if e.State != "ESTABLISHED" {
		t.Errorf("State = %q, want ESTABLISHED (tcp_conntrack enum 3)", e.State)
	}
	if e.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", e.Protocol)
	}
	if e.SrcIP != "192.0.2.1" || e.DstIP != "192.0.2.2" {
		t.Errorf("endpoints = %s -> %s", e.SrcIP, e.DstIP)
	}
}

// TestParseCTRejectsRecordWithoutEndpoints mirrors the /proc parser's guard.
func TestParseCTRejectsRecordWithoutEndpoints(t *testing.T) {
	body := nlaU32(ctaTimeout, 60) // timeout only, no tuple
	if _, ok := parseCT(body); ok {
		t.Error("accepted a record with no src/dst")
	}
}

// TestParseAttrsSurvivesTruncation: these bytes come from the kernel, but a
// short read or an unknown future layout must degrade to fewer fields, never
// to an out-of-range slice panic.
func TestParseAttrsSurvivesTruncation(t *testing.T) {
	full := buildCT(t, 6, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, 22, 443, 300, 3)
	for cut := len(full); cut > 0; cut-- {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte truncation: %v", cut, r)
				}
			}()
			parseCT(full[:cut]) // result irrelevant; must not panic
		}()
	}
	// A length field that claims more than the buffer holds.
	bad := []byte{0xff, 0xff, 0x01, 0x00, 0x00, 0x00}
	if got := parseAttrs(bad); len(got) != 0 {
		t.Errorf("parseAttrs accepted an over-long attribute: %v", got)
	}
}

// TestParseDumpHonoursLimit: the cap must hold across a buffer that carries
// several messages, or a busy host balloons the API response.
func TestParseDumpHonoursLimit(t *testing.T) {
	msgs := loadFixture(t)
	buf := wrapMessages(t, msgs, false)

	out, done, err := parseDump(buf, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Errorf("got %d entries, want the limit of 3", len(out))
	}
	if !done {
		t.Error("hitting the limit must stop the dump")
	}

	// have>0 accounts for entries collected from earlier buffers.
	out, _, err = parseDump(buf, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("got %d entries with have=2 and limit=3, want 1", len(out))
	}
}

// TestParseDumpStopsAtDone: NLMSG_DONE terminates the multipart dump.
func TestParseDumpStopsAtDone(t *testing.T) {
	msgs := loadFixture(t)
	buf := wrapMessages(t, msgs[:5], true)
	out, done, err := parseDump(buf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !done {
		t.Error("NLMSG_DONE not detected")
	}
	if len(out) != 5 {
		t.Errorf("got %d entries, want 5", len(out))
	}
}

// TestParseDumpSurfacesNetlinkError: EPERM from an unprivileged dump must
// become a real error, not zero entries. This is exactly what an unprivileged
// caller sees, and what the handler now turns into a 503.
func TestParseDumpSurfacesNetlinkError(t *testing.T) {
	msg := make([]byte, nlMsgHdrLen+4)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], syscall.NLMSG_ERROR)
	eperm := int32(syscall.EPERM)
	binary.LittleEndian.PutUint32(msg[nlMsgHdrLen:], uint32(-eperm))

	_, done, err := parseDump(msg, 0, 0)
	if err == nil {
		t.Fatal("NLMSG_ERROR was swallowed — an unreadable table would look empty")
	}
	if !done {
		t.Error("an error must end the dump")
	}
	if !strings.Contains(err.Error(), "operation not permitted") {
		t.Errorf("err = %v, want it to name EPERM", err)
	}
}

// TestParseDumpAckIsNotAnError: errno 0 in an NLMSG_ERROR is an ACK.
func TestParseDumpAckIsNotAnError(t *testing.T) {
	msg := make([]byte, nlMsgHdrLen+4)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], syscall.NLMSG_ERROR)
	binary.LittleEndian.PutUint32(msg[nlMsgHdrLen:], 0)

	if _, _, err := parseDump(msg, 0, 0); err != nil {
		t.Errorf("an ACK was reported as an error: %v", err)
	}
}

// TestProtoNameUnknownIsNumeric: an untracked L4 protocol is shown, not dropped.
func TestProtoNameUnknownIsNumeric(t *testing.T) {
	if got := protoName(47); got != "proto-47" {
		t.Errorf("protoName(47) = %q, want proto-47", got)
	}
	if got := protoName(6); got != "tcp" {
		t.Errorf("protoName(6) = %q, want tcp", got)
	}
}

/* ---------- fixture helpers ---------- */

func nla(typ uint16, payload []byte) []byte {
	l := 4 + len(payload)
	b := make([]byte, nlAlign(l))
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], payload)
	return b
}

func nlaU32(typ uint16, v uint32) []byte {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, v)
	return nla(typ, p)
}

func nlaBE16(typ uint16, v uint16) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, v)
	return nla(typ, p)
}

// buildCT assembles one ctnetlink message body with the same nesting the
// kernel uses, for the cases the captured dump does not happen to contain.
func buildCT(t *testing.T, proto uint8, src, dst []byte, sport, dport uint16, timeout uint32, tcpState uint8) []byte {
	t.Helper()
	ip := append(nla(ctaIPv4Src, src), nla(ctaIPv4Dst, dst)...)
	pr := nla(ctaProtoNum, []byte{proto})
	pr = append(pr, nlaBE16(ctaProtoSrcPort, sport)...)
	pr = append(pr, nlaBE16(ctaProtoDstPort, dport)...)

	tuple := append(nla(ctaTupleIP, ip), nla(ctaTupleProto, pr)...)

	body := nla(ctaTupleOrig, tuple)
	body = append(body, nlaU32(ctaTimeout, timeout)...)
	tcpInfo := nla(ctaProtoinfoTCPState, []byte{tcpState})
	body = append(body, nla(ctaProtoinfo, nla(ctaProtoinfoTCP, tcpInfo))...)
	return body
}

// wrapMessages puts nlmsghdr + nfgenmsg back around each captured body so the
// message-loop code sees exactly what recvfrom hands it.
func wrapMessages(t *testing.T, bodies [][]byte, appendDone bool) []byte {
	t.Helper()
	var buf []byte
	for _, body := range bodies {
		total := ctPayloadOff + len(body)
		msg := make([]byte, nlAlign(total))
		binary.LittleEndian.PutUint32(msg[0:], uint32(total))
		binary.LittleEndian.PutUint16(msg[4:], (nfnlSubsysCtnetlink<<8)|ipctnlMsgCtGet)
		copy(msg[ctPayloadOff:], body)
		buf = append(buf, msg...)
	}
	if appendDone {
		done := make([]byte, nlMsgHdrLen)
		binary.LittleEndian.PutUint32(done[0:], uint32(len(done)))
		binary.LittleEndian.PutUint16(done[4:], syscall.NLMSG_DONE)
		buf = append(buf, done...)
	}
	return buf
}
