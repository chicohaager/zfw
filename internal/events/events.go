// Package events parses kernel-log entries produced by the ZFW iptables LOG
// targets and turns them into the structured event stream the UI's Events
// tab consumes. The source of truth is journald (`journalctl -k -o json`)
// so retention is whatever the user's journald is configured for and ZFW
// stores no separate event database.
package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Event is one logged firewall drop, suitable for direct JSON encoding to
// the UI. Port is 0 when the protocol carries no port number (e.g. ICMP).
// Threats is set by classify() (v0.4.2 — port-scan / brute-force flags);
// omitempty so an event the classifier did not flag stays compact on the
// wire and the UI's `if (ev.threats)` branch sees undefined, not [].
type Event struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	Zone     string    `json:"zone"` // "host" | "docker"
	Threats  []string  `json:"threats,omitempty"`
}

// Threat classifier thresholds. Externalised as consts so the tests use
// the exact same numbers documented in the README/ROADMAP — a drift
// between code and docs would mean "we said 10 ports, we flag at 8" is
// silently true.
const (
	// portScanPortThreshold: a source must hit at least this many distinct
	// dest ports within portScanWindow to be flagged.
	portScanPortThreshold = 10
	portScanWindow        = time.Minute

	// bruteForceHitThreshold: a source must hit the same dest port at
	// least this many times within bruteForceWindow to be flagged.
	// Limited to the high-risk ports the auth attack catalogue cares
	// about (SSH, SMB, RDP, web admin panels) so we do not light up on
	// every UDP scan that fits the count.
	bruteForceHitThreshold = 20
	bruteForceWindow       = time.Minute
)

// bruteForceTargets lists the dest ports the brute-force classifier
// considers. Misses on these are far more interesting (credential
// guessing) than misses on a random ephemeral port; flagging every
// 20-hit burst regardless of port would drown the signal.
var bruteForceTargets = map[int]bool{
	22:   true, // SSH
	445:  true, // SMB
	3389: true, // RDP
	8888: true, // common web admin
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
	// R3-8 (v1.0.2): capture stderr so a journalctl failure is observable
	// at slog.Debug. The Events tab's "transient hiccup = empty list" UX
	// is preserved (the function still returns no error and no events),
	// but an operator running with debug logging on can now diagnose a
	// persistent failure (read-only /var/log/journal, missing journalctl
	// binary on a stripped image, AppArmor profile, etc.) without
	// guessing.
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
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
	// R3-8: log Wait error + captured stderr at Debug so a persistent
	// journalctl problem is diagnosable. The function intentionally
	// still returns nil error — the events tab fails soft (empty list
	// on hiccup) by design, callers must not see I/O errors here.
	if werr := cmd.Wait(); werr != nil {
		slog.Debug("journalctl exited non-zero",
			"err", werr,
			"stderr", strings.TrimSpace(stderrBuf.String()))
	} else if stderrBuf.Len() > 0 {
		slog.Debug("journalctl wrote stderr but exited cleanly",
			"stderr", strings.TrimSpace(stderrBuf.String()))
	}

	// Classify on the time-ascending series so the sliding window walks
	// forward naturally. Then reverse for the UI's newest-first
	// convention. Threats are stamped on the events themselves; the UI
	// reads ev.threats per row + renders a banner when any are present.
	out = Classify(out)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Classify scans the (time-ascending) event series and stamps Threats on
// each event whose source crossed a port-scan or brute-force threshold.
// Modifies the slice in place and returns it for chaining. Safe to call
// on an empty slice. Exported for testability — Read() always calls it
// before reversing for output.
func Classify(events []Event) []Event {
	if len(events) == 0 {
		return events
	}
	// Group event indices by source IP. The empty source is treated as a
	// distinct bucket so a parsing failure does not collapse the rest of
	// the keyspace into one false-positive scan.
	bySource := map[string][]int{}
	for i, e := range events {
		bySource[e.Source] = append(bySource[e.Source], i)
	}
	for _, idxs := range bySource {
		classifySource(events, idxs)
	}
	return events
}

func classifySource(events []Event, idxs []int) {
	// Sliding window over the indices, exploiting that events were
	// inserted in time-ascending order (journalctl --since … emits
	// oldest-first; Read() does not reverse until after Classify).
	left := 0
	portsInWindow := map[int]int{} // dest port -> count within current window
	portPortHits := map[int]int{}  // dest port -> count for brute-force
	for right, ri := range idxs {
		// Shrink the window from the left until [left..right] fits the
		// largest classifier window. Both classifiers happen to use
		// the same 60s window, so one shrink loop covers both.
		for left < right {
			li := idxs[left]
			if events[ri].Time.Sub(events[li].Time) <= portScanWindow {
				break
			}
			// Evict the left event from the window's port histograms.
			p := events[li].Port
			if p > 0 {
				portsInWindow[p]--
				if portsInWindow[p] == 0 {
					delete(portsInWindow, p)
				}
				portPortHits[p]--
				if portPortHits[p] == 0 {
					delete(portPortHits, p)
				}
			}
			left++
		}
		// Add the right event to the window's histograms.
		p := events[ri].Port
		if p > 0 {
			portsInWindow[p]++
			portPortHits[p]++
		}

		// Port-scan: ≥ portScanPortThreshold distinct dest ports in window.
		if len(portsInWindow) >= portScanPortThreshold {
			addThreat(&events[ri], "port_scan")
		}
		// Brute-force: same source × same dest port × bruteForceTargets,
		// hitting bruteForceHitThreshold within the window.
		if p > 0 && bruteForceTargets[p] && portPortHits[p] >= bruteForceHitThreshold {
			addThreat(&events[ri], "brute_force")
		}
	}
}

func addThreat(e *Event, t string) {
	for _, existing := range e.Threats {
		if existing == t {
			return
		}
	}
	e.Threats = append(e.Threats, t)
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
	// CQ-15 (v1.0.2): use SplitN(_, "=", 2) instead of strings.Cut so a
	// value containing further '=' chars stays intact (current kernels
	// don't produce that shape, but kernel format drifts and we should
	// not silently truncate).
	fields := map[string]string{}
	for _, f := range strings.Fields(msg) {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) == 2 && kv[1] != "" {
			fields[kv[0]] = kv[1]
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
