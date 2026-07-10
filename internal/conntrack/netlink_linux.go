//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// ctnetlink (NETLINK_NETFILTER / NFNL_SUBSYS_CTNETLINK) is the only
// conntrack interface a stock ZimaOS kernel exposes:
//
//	CONFIG_NF_CONNTRACK=y
//	# CONFIG_NF_CONNTRACK_PROCFS is not set   <- /proc/net/nf_conntrack never appears
//	CONFIG_NF_CT_NETLINK=y                    <- this
//
// and conntrack(8) is not part of the image either, so both pre-v1.0.19
// sources failed and the Connections tab was permanently empty (issue #1).
//
// Dumping the table needs CAP_NET_ADMIN; unprivileged callers get EPERM,
// which surfaces as a real error rather than an empty list.
const (
	netlinkNetfilter = 12 // NETLINK_NETFILTER

	nfnlSubsysCtnetlink = 1 // NFNL_SUBSYS_CTNETLINK
	ipctnlMsgCtGet      = 1 // IPCTNL_MSG_CT_GET

	// nlmsghdr(16) + nfgenmsg(4). Every ctnetlink message body starts
	// after both, at the first netlink attribute.
	nlMsgHdrLen  = 16
	nfGenMsgLen  = 4
	ctPayloadOff = nlMsgHdrLen + nfGenMsgLen

	nlaTypeMask = 0x3fff // strips NLA_F_NESTED | NLA_F_NET_BYTEORDER

	// Top-level CTA_* attributes we consume.
	ctaTupleOrig = 1
	ctaProtoinfo = 4
	ctaTimeout   = 7

	// Inside CTA_TUPLE_ORIG.
	ctaTupleIP    = 1
	ctaTupleProto = 2

	// Inside CTA_TUPLE_IP.
	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	// Inside CTA_TUPLE_PROTO.
	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	// Inside CTA_PROTOINFO.
	ctaProtoinfoTCP      = 1
	ctaProtoinfoTCPState = 1

	defaultRecvTimeout = 5 * time.Second
	recvBufSize        = 1 << 20 // a dump message never exceeds this
)

// tcpStates maps the kernel's enum tcp_conntrack to the names conntrack(8)
// and /proc/net/nf_conntrack print, so the UI shows one vocabulary no
// matter which source produced the row.
var tcpStates = [...]string{
	"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT",
	"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2",
}

// protoNames covers what a NAS actually tracks; anything else is rendered
// numerically rather than dropped.
func protoName(n uint8) string {
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("proto-%d", n)
}

func nlAlign(n int) int { return (n + 3) &^ 3 }

type nlAttr struct {
	typ  uint16
	data []byte
}

// parseAttrs walks a netlink attribute block. A truncated or nonsensical
// attribute ends the walk instead of panicking: these bytes come from the
// kernel, but a short read or a future attribute layout must degrade to
// "fewer fields", never to an out-of-range slice.
func parseAttrs(b []byte) []nlAttr {
	var out []nlAttr
	for len(b) >= 4 {
		length := int(binary.LittleEndian.Uint16(b[0:2]))
		typ := binary.LittleEndian.Uint16(b[2:4])
		if length < 4 || length > len(b) {
			break
		}
		out = append(out, nlAttr{typ: typ & nlaTypeMask, data: b[4:length]})
		step := nlAlign(length)
		if step >= len(b) {
			break
		}
		b = b[step:]
	}
	return out
}

// parseCT turns one ctnetlink message body (the attributes after nfgenmsg)
// into an Entry. Only CTA_TUPLE_ORIG is read — the reply tuple describes the
// same flow backwards and the UI asks "who initiated what", matching the
// original-direction-only rule of the /proc parser.
//
// Ports and the timeout are network byte order inside the attribute payload;
// the attribute headers themselves are host byte order. Mixing those up is
// the classic ctnetlink bug, so each is decoded explicitly.
func parseCT(payload []byte) (Entry, bool) {
	var e Entry
	var proto uint8
	haveProto := false

	for _, a := range parseAttrs(payload) {
		switch a.typ {
		case ctaTimeout:
			if len(a.data) == 4 {
				e.AgeSec = int(binary.BigEndian.Uint32(a.data))
			}
		case ctaTupleOrig:
			for _, t := range parseAttrs(a.data) {
				switch t.typ {
				case ctaTupleIP:
					for _, ip := range parseAttrs(t.data) {
						switch ip.typ {
						case ctaIPv4Src, ctaIPv6Src:
							e.SrcIP = ipString(ip.data)
						case ctaIPv4Dst, ctaIPv6Dst:
							e.DstIP = ipString(ip.data)
						}
					}
				case ctaTupleProto:
					for _, p := range parseAttrs(t.data) {
						switch p.typ {
						case ctaProtoNum:
							if len(p.data) == 1 {
								proto, haveProto = p.data[0], true
							}
						case ctaProtoSrcPort:
							if len(p.data) == 2 {
								e.SrcPort = int(binary.BigEndian.Uint16(p.data))
							}
						case ctaProtoDstPort:
							if len(p.data) == 2 {
								e.DstPort = int(binary.BigEndian.Uint16(p.data))
							}
						}
					}
				}
			}
		case ctaProtoinfo:
			for _, pi := range parseAttrs(a.data) {
				if pi.typ != ctaProtoinfoTCP {
					continue
				}
				for _, tcp := range parseAttrs(pi.data) {
					if tcp.typ == ctaProtoinfoTCPState && len(tcp.data) == 1 {
						if s := int(tcp.data[0]); s < len(tcpStates) {
							e.State = tcpStates[s]
						}
					}
				}
			}
		}
	}
	if haveProto {
		e.Protocol = protoName(proto)
	}
	// Same guard as the /proc parser: the kernel can emit a record without
	// a usable tuple while a flow is still being set up.
	if e.SrcIP == "" || e.DstIP == "" {
		return Entry{}, false
	}
	return e, true
}

func ipString(b []byte) string {
	if len(b) != 4 && len(b) != 16 {
		return ""
	}
	return net.IP(b).String()
}

// readNetlink dumps the conntrack table over ctnetlink. limit caps the
// result; 0 means no cap.
func readNetlink(ctx context.Context, limit int) ([]Entry, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	// A netlink recvfrom has no deadline of its own — without SO_RCVTIMEO a
	// stalled dump would pin the API request until the client gave up.
	if err := setRecvTimeout(fd, recvTimeout(ctx)); err != nil {
		return nil, fmt.Errorf("set timeout: %w", err)
	}

	const seq = 1
	req := make([]byte, ctPayloadOff)
	binary.LittleEndian.PutUint32(req[0:], uint32(len(req)))
	binary.LittleEndian.PutUint16(req[4:], (nfnlSubsysCtnetlink<<8)|ipctnlMsgCtGet)
	binary.LittleEndian.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:], seq)
	binary.LittleEndian.PutUint32(req[12:], 0) // pid: let the kernel fill it in
	req[16] = syscall.AF_UNSPEC                // nfgen_family: both families
	req[17] = 0                                // NFNETLINK_V0
	binary.BigEndian.PutUint16(req[18:], 0)    // res_id

	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sendto: %w", err)
	}

	buf := make([]byte, recvBufSize)
	var out []Entry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("recvfrom: %w", err)
		}
		entries, done, err := parseDump(buf[:n], limit, len(out))
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
		// Stop reading the moment the cap is reached. The socket is closed
		// on return, so the kernel drops the rest of the dump for us.
		if done || (limit > 0 && len(out) >= limit) {
			return out, nil
		}
	}
}

// parseDump consumes one recvfrom buffer of (possibly several) netlink
// messages. have is how many entries the caller already holds, so the cap
// is honoured across buffers. done reports NLMSG_DONE.
func parseDump(b []byte, limit, have int) (out []Entry, done bool, err error) {
	for len(b) >= nlMsgHdrLen {
		length := int(binary.LittleEndian.Uint32(b[0:4]))
		typ := binary.LittleEndian.Uint16(b[4:6])
		if length < nlMsgHdrLen || length > len(b) {
			// Truncated trailer: everything parsed so far still stands.
			break
		}
		switch typ {
		case syscall.NLMSG_DONE:
			return out, true, nil
		case syscall.NLMSG_ERROR:
			if length < nlMsgHdrLen+4 {
				return out, true, fmt.Errorf("netlink: malformed error message")
			}
			errno := int32(binary.LittleEndian.Uint32(b[nlMsgHdrLen : nlMsgHdrLen+4]))
			if errno == 0 { // an ACK, not an error
				return out, true, nil
			}
			return nil, true, fmt.Errorf("netlink: %w", syscall.Errno(-errno))
		case syscall.NLMSG_NOOP:
		default:
			if length >= ctPayloadOff {
				if e, ok := parseCT(b[ctPayloadOff:length]); ok {
					out = append(out, e)
					if limit > 0 && have+len(out) >= limit {
						return out, true, nil
					}
				}
			}
		}
		step := nlAlign(length)
		if step >= len(b) {
			break
		}
		b = b[step:]
	}
	return out, false, nil
}

func recvTimeout(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return defaultRecvTimeout
	}
	if d := time.Until(dl); d > 0 && d < defaultRecvTimeout {
		return d
	}
	return defaultRecvTimeout
}

func setRecvTimeout(fd int, d time.Duration) error {
	tv := syscall.NsecToTimeval(int64(d))
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}
