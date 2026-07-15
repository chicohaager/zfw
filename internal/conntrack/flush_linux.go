//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
)

const (
	ipctnlMsgCtDelete = 2      // IPCTNL_MSG_CT_DELETE
	nlaFNested        = 0x8000 // NLA_F_NESTED
)

// protoNum is the inverse of protoName for the two protocols Flush targets.
// Anything else returns (0, false) and is skipped — icmp and friends carry no
// port to key a targeted flush on.
func protoNum(name string) (uint8, bool) {
	switch name {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	}
	return 0, false
}

// encodeAttr encodes one netlink attribute: a 4-byte header (length incl. header,
// type) followed by data, padded to a 4-byte boundary. The length field is the
// unpadded length, matching the kernel's own encoding.
func encodeAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, nlAlign(l))
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

// buildCTDelete assembles an IPCTNL_MSG_CT_DELETE request identifying one flow
// by its original tuple (src/dst IP, src/dst port, proto). Ports are network
// byte order, as ctnetlink expects. Returns an error for an entry without a
// port-bearing protocol or an unparseable address.
func buildCTDelete(seq uint32, e Entry) ([]byte, error) {
	pnum, ok := protoNum(e.Protocol)
	if !ok {
		return nil, fmt.Errorf("conntrack flush: unsupported proto %q", e.Protocol)
	}
	sip, dip := net.ParseIP(e.SrcIP), net.ParseIP(e.DstIP)
	if sip == nil || dip == nil {
		return nil, fmt.Errorf("conntrack flush: bad ip src=%q dst=%q", e.SrcIP, e.DstIP)
	}

	var family byte
	var sb, db []byte
	var srcType, dstType uint16
	if s4, d4 := sip.To4(), dip.To4(); s4 != nil && d4 != nil {
		family, sb, db, srcType, dstType = syscall.AF_INET, s4, d4, ctaIPv4Src, ctaIPv4Dst
	} else {
		family, sb, db, srcType, dstType = syscall.AF_INET6, sip.To16(), dip.To16(), ctaIPv6Src, ctaIPv6Dst
	}

	ipAttr := encodeAttr(ctaTupleIP|nlaFNested, concat(encodeAttr(srcType, sb), encodeAttr(dstType, db)))

	sp := make([]byte, 2)
	binary.BigEndian.PutUint16(sp, uint16(e.SrcPort))
	dp := make([]byte, 2)
	binary.BigEndian.PutUint16(dp, uint16(e.DstPort))
	protoAttr := encodeAttr(ctaTupleProto|nlaFNested, concat(
		encodeAttr(ctaProtoNum, []byte{pnum}),
		encodeAttr(ctaProtoSrcPort, sp),
		encodeAttr(ctaProtoDstPort, dp),
	))

	tuple := encodeAttr(ctaTupleOrig|nlaFNested, concat(ipAttr, protoAttr))

	// nfgenmsg: family, NFNETLINK_V0, res_id(0, big-endian).
	nfgen := []byte{family, 0, 0, 0}
	body := concat(nfgen, tuple)

	msg := make([]byte, nlMsgHdrLen+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], (nfnlSubsysCtnetlink<<8)|ipctnlMsgCtDelete)
	binary.LittleEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:], seq)
	binary.LittleEndian.PutUint32(msg[12:], 0) // pid: kernel fills in
	copy(msg[nlMsgHdrLen:], body)
	return msg, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// flushImpl dumps the table once, then deletes every entry whose original
// destination port matches a target. Delete failures are collected rather than
// aborting the sweep — one stubborn flow must not block tearing down the rest.
func flushImpl(ctx context.Context, targets []PortKey) (int, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	want := make(map[PortKey]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}

	entries, err := readNetlink(ctx, 0)
	if err != nil {
		return 0, fmt.Errorf("conntrack flush: dump: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return 0, fmt.Errorf("conntrack flush: socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("conntrack flush: bind: %w", err)
	}
	if err := setRecvTimeout(fd, recvTimeout(ctx)); err != nil {
		return 0, fmt.Errorf("conntrack flush: set timeout: %w", err)
	}

	var errs []error
	deleted := 0
	seq := uint32(1)
	for _, e := range entries {
		if !want[PortKey{Proto: e.Protocol, Port: e.DstPort}] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		seq++
		if err := deleteEntry(fd, seq, e); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted++
	}
	return deleted, errors.Join(errs...)
}

// deleteEntry sends one CT_DELETE and waits for its ACK. An ENOENT means the
// flow expired between the dump and now — success, not failure.
func deleteEntry(fd int, seq uint32, e Entry) error {
	msg, err := buildCTDelete(seq, e)
	if err != nil {
		return err
	}
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("recvfrom: %w", err)
	}
	return parseAck(buf[:n])
}

// parseAck reads the NLMSG_ERROR that terminates a request. errno 0 is an ACK;
// -ENOENT is treated as success (nothing to delete).
func parseAck(b []byte) error {
	if len(b) < nlMsgHdrLen {
		return fmt.Errorf("netlink: short ack")
	}
	typ := binary.LittleEndian.Uint16(b[4:6])
	if typ != syscall.NLMSG_ERROR {
		return nil // an unexpected non-error message; the delete was accepted
	}
	if len(b) < nlMsgHdrLen+4 {
		return fmt.Errorf("netlink: malformed error message")
	}
	errno := int32(binary.LittleEndian.Uint32(b[nlMsgHdrLen : nlMsgHdrLen+4]))
	if errno == 0 || syscall.Errno(-errno) == syscall.ENOENT {
		return nil
	}
	return fmt.Errorf("netlink delete: %w", syscall.Errno(-errno))
}
