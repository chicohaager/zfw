// Package events parses kernel-log entries produced by the ZFW iptables LOG
// targets and turns them into the structured event stream the UI's Events
// tab consumes. The source of truth is journald (`journalctl -k -o json`)
// so retention is whatever the user's journald is configured for and ZFW
// stores no separate event database.
package events

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Event is one logged firewall drop, suitable for direct JSON encoding to
// the UI. Port is 0 when the protocol carries no port number (e.g. ICMP).
type Event struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	Zone     string    `json:"zone"` // "host" | "docker"
}

// Read returns the most recent drop events since `since`, newest-first, up
// to `limit`. A nil/empty result with no error means "no drops in that
// window" — distinguish from "journalctl unavailable" by the error return.
func Read(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "journalctl",
		"-k", "--no-pager", "-o", "json",
		"--since", since.UTC().Format("2006-01-02 15:04:05"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// journalctl may emit large lines for verbose kernel messages — give the
	// scanner enough headroom so a long iptables LOG line is not silently
	// truncated.
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<14), 1<<20)

	var out []Event
	for sc.Scan() {
		var entry struct {
			Msg string `json:"MESSAGE"`
			Ts  string `json:"__REALTIME_TIMESTAMP"`
		}
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			continue
		}
		ev, ok := parseDropLine(entry.Msg, entry.Ts)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	_ = cmd.Wait() // ignore: journalctl exit code is not load-bearing here

	// Newest-first so the UI table sorts naturally without client-side work.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// parseDropLine extracts the fields ZFW writes via the iptables LOG target.
// Returns ok=false for any message that did not originate in a ZFW chain
// so the caller can skip it without further filtering.
func parseDropLine(msg, ts string) (Event, bool) {
	var zone string
	switch {
	case strings.HasPrefix(msg, "ZFW-IN6-DROP"):
		// Match before "ZFW-IN-DROP" so the longer prefix wins.
		zone = "host6"
	case strings.HasPrefix(msg, "ZFW-IN-DROP"):
		zone = "host"
	case strings.HasPrefix(msg, "ZFW-DOCK-DROP"):
		zone = "docker"
	default:
		return Event{}, false
	}
	// iptables LOG writes space-separated KEY=VALUE pairs after the prefix.
	fields := map[string]string{}
	for _, f := range strings.Fields(msg) {
		k, v, ok := strings.Cut(f, "=")
		if ok && v != "" {
			fields[k] = v
		}
	}
	ev := Event{
		Source:   fields["SRC"],
		Protocol: strings.ToLower(fields["PROTO"]),
		Zone:     zone,
	}
	if p, err := strconv.Atoi(fields["DPT"]); err == nil {
		ev.Port = p
	}
	if usec, err := strconv.ParseInt(ts, 10, 64); err == nil {
		ev.Time = time.UnixMicro(usec)
	}
	return ev, true
}
