// Package conntrack reads the kernel's live connection-tracking table
// and exposes it as structured Entry records for the UI's Connections
// tab. Source-of-truth is /proc/net/nf_conntrack (always available when
// the kernel module is loaded — which it is on every ZimaOS host
// because ZFW already depends on conntrack matches). The conntrack(8)
// userland tool is tried as a fall-through only.
//
// Read caps the result at a configurable limit so a host with tens of
// thousands of connections does not balloon the API response.
package conntrack

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Entry is one connection-tracking record, original direction only.
// Reply direction is dropped — the UI cares about "who initiated what".
type Entry struct {
	Protocol string `json:"protocol"`        // tcp, udp, icmp, ...
	State    string `json:"state,omitempty"` // ESTABLISHED, TIME_WAIT, ASSURED, ... (omitempty for stateless protocols)
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port,omitempty"`
	// AgeSec is the kernel's timeout countdown — how long until the
	// entry expires if no further traffic flows. Bigger = more recent
	// (TCP ESTABLISHED defaults to ~5 days; UDP to seconds).
	AgeSec int `json:"age_sec"`
}

// Read returns the live conntrack table. limit caps the result; pass
// 0 for "no cap" (use sparingly — a busy host can have 100k+ entries).
// Errors only on I/O failure; an empty table is (nil, nil).
func Read(ctx context.Context, limit int) ([]Entry, error) {
	if entries, err := readProc(ctx, limit); err == nil {
		return entries, nil
	} else if entries, err := readCmd(ctx, limit); err == nil {
		return entries, nil
	} else {
		return nil, err
	}
}

// readProc parses /proc/net/nf_conntrack. The file's line format is
// stable across modern kernels: "<proto-name> <proto-num> <timeout>
// [<state>] src=… dst=… sport=… dport=… [src=… …] [ASSURED] [UNREPLIED]
// mark=… secctx=… zone=… use=…". We take the first src/dst pair (the
// original direction) and skip the reply pair that follows.
func readProc(ctx context.Context, limit int) ([]Entry, error) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseStream(ctx, f, limit)
}

// readCmd falls back to `conntrack -L -o extended` when /proc reading
// is not available (containerised tests, hosts with conntrack disabled
// in the kernel build but the userland tool present, etc.).
func readCmd(ctx context.Context, limit int) ([]Entry, error) {
	cmd := exec.CommandContext(ctx, "conntrack", "-L", "-o", "extended")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, perr := parseStream(ctx, stdout, limit)
	// parseStream may stop early at `limit` — kill so Wait can't block
	// on a conntrack process stuck writing into the abandoned pipe.
	_ = cmd.Process.Kill()
	_ = cmd.Wait() // conntrack exit code isn't load-bearing here
	return out, perr
}

// parseStream consumes a conntrack stream line-by-line and emits one
// Entry per line, stopping as soon as `limit` entries are collected
// (limit 0 = no cap) — a busy host can have 100k+ entries and parsing
// them all just to slice the first 500 defeats the cap's purpose.
// Lines that don't parse are silently skipped — a stray kernel-only
// entry type must not abort the whole read.
func parseStream(ctx context.Context, r interface{ Read(p []byte) (int, error) }, limit int) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<14), 1<<20)
	var out []Entry
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		ev, ok := parseLine(sc.Text())
		if !ok {
			continue
		}
		out = append(out, ev)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// parseLine extracts a single Entry from one nf_conntrack / conntrack
// output line. The original-direction `src=` always precedes the reply
// `src=`, so we take the first occurrence of each key.
//
// Two on-disk shapes are handled transparently:
//
//	/proc/net/nf_conntrack:  "ipv4 2 tcp 6 431999 ESTABLISHED src=…"
//	conntrack -L -o extended: "tcp      6 431999 ESTABLISHED src=…"
//
// The L3 prefix ("ipv4 2") is stripped when present so downstream
// indexing into fields[] is the same shape either way.
func parseLine(line string) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) >= 3 && (fields[0] == "ipv4" || fields[0] == "ipv6") {
		fields = fields[2:]
	}
	// After the optional L3 strip: fields[0]=proto name, fields[1]=
	// proto number (fixed per proto: tcp=6, udp=17, icmp=1, ...),
	// fields[2]=timeout countdown in seconds, fields[3+]=state +
	// src=… dst=… sport=… dport=… key=value pairs.
	if len(fields) < 4 {
		return Entry{}, false
	}
	e := Entry{Protocol: fields[0]}
	if n, err := strconv.Atoi(fields[2]); err == nil {
		e.AgeSec = n
	}
	// First-occurrence wins: original-direction src/dst.
	seenSrc := false
	seenDst := false
	seenSport := false
	seenDport := false
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if ok {
			switch k {
			case "src":
				if !seenSrc {
					e.SrcIP = v
					seenSrc = true
				}
			case "dst":
				if !seenDst {
					e.DstIP = v
					seenDst = true
				}
			case "sport":
				if !seenSport {
					if p, err := strconv.Atoi(v); err == nil {
						e.SrcPort = p
					}
					seenSport = true
				}
			case "dport":
				if !seenDport {
					if p, err := strconv.Atoi(v); err == nil {
						e.DstPort = p
					}
					seenDport = true
				}
			}
			continue
		}
		// Bare tokens are state names (ESTABLISHED, TIME_WAIT, ...)
		// or flags (ASSURED, UNREPLIED). Take the first state-shaped
		// token (all-caps, no =) so flags don't overwrite states.
		if e.State == "" && isStateToken(f) {
			e.State = f
		}
	}
	// Filter obviously-broken records (kernel emits one without src/dst
	// during connection setup for some L4 protos).
	if e.SrcIP == "" || e.DstIP == "" {
		return Entry{}, false
	}
	return e, true
}

// isStateToken reports whether s looks like a conntrack state name. We
// don't enumerate all states; the heuristic (all-caps, no '=') is
// enough to distinguish from flag suffixes like [ASSURED] (the brackets
// are not in /proc output, but the token "ASSURED" appears alone) and
// from numeric counters.
func isStateToken(s string) bool {
	if s == "" || strings.ContainsAny(s, "=[]") {
		return false
	}
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || r == '_') {
			return false
		}
	}
	return true
}
