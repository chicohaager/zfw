//go:build linux

package conntrack

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// findAttr walks a netlink attribute block and returns the payload of the first
// attribute whose type (with flag bits stripped) matches typ.
func findAttr(t *testing.T, b []byte, typ uint16) []byte {
	t.Helper()
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		aType := binary.LittleEndian.Uint16(b[2:4]) & nlaTypeMask
		if l < 4 || l > len(b) {
			t.Fatalf("bad attr len %d in % x", l, b)
		}
		if aType == typ {
			return b[4:l]
		}
		b = b[nlAlign(l):]
	}
	return nil
}

func TestBuildCTDeleteV4(t *testing.T) {
	e := Entry{
		Protocol: "tcp",
		SrcIP:    "192.168.1.175",
		SrcPort:  59377,
		DstIP:    "192.168.1.143",
		DstPort:  7070,
	}
	msg, err := buildCTDelete(42, e)
	if err != nil {
		t.Fatalf("buildCTDelete: %v", err)
	}

	// --- nlmsghdr ---
	if got := binary.LittleEndian.Uint32(msg[0:4]); int(got) != len(msg) {
		t.Errorf("nlmsg_len = %d, want %d", got, len(msg))
	}
	wantType := uint16(nfnlSubsysCtnetlink<<8) | ipctnlMsgCtDelete
	if got := binary.LittleEndian.Uint16(msg[4:6]); got != wantType {
		t.Errorf("nlmsg_type = %#x, want %#x", got, wantType)
	}
	wantFlags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	if got := binary.LittleEndian.Uint16(msg[6:8]); got != wantFlags {
		t.Errorf("nlmsg_flags = %#x, want %#x", got, wantFlags)
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != 42 {
		t.Errorf("nlmsg_seq = %d, want 42", got)
	}

	// --- nfgenmsg ---
	if msg[nlMsgHdrLen] != syscall.AF_INET {
		t.Errorf("family = %d, want AF_INET(%d)", msg[nlMsgHdrLen], syscall.AF_INET)
	}

	// --- CTA_TUPLE_ORIG -> CTA_TUPLE_IP / CTA_TUPLE_PROTO ---
	attrs := msg[ctPayloadOff:]
	tuple := findAttr(t, attrs, ctaTupleOrig)
	if tuple == nil {
		t.Fatal("no CTA_TUPLE_ORIG")
	}
	ipBlk := findAttr(t, tuple, ctaTupleIP)
	if ipBlk == nil {
		t.Fatal("no CTA_TUPLE_IP")
	}
	src := findAttr(t, ipBlk, ctaIPv4Src)
	dst := findAttr(t, ipBlk, ctaIPv4Dst)
	if want := []byte{192, 168, 1, 175}; string(src) != string(want) {
		t.Errorf("src ip = % d, want % d", src, want)
	}
	if want := []byte{192, 168, 1, 143}; string(dst) != string(want) {
		t.Errorf("dst ip = % d, want % d", dst, want)
	}

	protoBlk := findAttr(t, tuple, ctaTupleProto)
	if protoBlk == nil {
		t.Fatal("no CTA_TUPLE_PROTO")
	}
	if num := findAttr(t, protoBlk, ctaProtoNum); len(num) != 1 || num[0] != 6 {
		t.Errorf("proto num = % d, want [6]", num)
	}
	// Ports must be network byte order (big-endian).
	if sp := findAttr(t, protoBlk, ctaProtoSrcPort); binary.BigEndian.Uint16(sp) != 59377 {
		t.Errorf("src port = %d, want 59377", binary.BigEndian.Uint16(sp))
	}
	if dp := findAttr(t, protoBlk, ctaProtoDstPort); binary.BigEndian.Uint16(dp) != 7070 {
		t.Errorf("dst port = %d, want 7070", binary.BigEndian.Uint16(dp))
	}
}

func TestBuildCTDeleteV6Family(t *testing.T) {
	e := Entry{Protocol: "udp", SrcIP: "fe80::1", SrcPort: 5353, DstIP: "fe80::2", DstPort: 5353}
	msg, err := buildCTDelete(1, e)
	if err != nil {
		t.Fatalf("buildCTDelete v6: %v", err)
	}
	if msg[nlMsgHdrLen] != syscall.AF_INET6 {
		t.Errorf("family = %d, want AF_INET6(%d)", msg[nlMsgHdrLen], syscall.AF_INET6)
	}
}

func TestBuildCTDeleteRejectsPortlessProto(t *testing.T) {
	if _, err := buildCTDelete(1, Entry{Protocol: "icmp", SrcIP: "1.2.3.4", DstIP: "5.6.7.8"}); err == nil {
		t.Fatal("expected error for icmp (no port to key on)")
	}
}
