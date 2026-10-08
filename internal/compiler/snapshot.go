package compiler

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// liveSnapshotPrefix marks the comment line, near the top of every compiled
// script, that records what the script was compiled from (v1.0.27).
//
// The engine copies the script it actually ran to applied.sh (and the
// confirmed one to committed.sh). Reading this line back from applied.sh is
// how the dashboard learns what is live: rules.json says what was saved, and
// compiled.sh what the daemon compiled last — neither is what the kernel
// holds after a save without an apply, or after dockerwatch recompiled for a
// newly published container port. Carrying the record inside the script
// keeps it atomic with the script: there is no second file that could be
// copied without the first.
const liveSnapshotPrefix = "# zfw-live: "

// LiveSnapshot is the record carried by liveSnapshotPrefix.
type LiveSnapshot struct {
	V int `json:"v"`
	// Rules is the binding-resolved rule set the script was compiled from,
	// without the free-text fields (Name, Notes): they are not needed to
	// judge reach and have no business in a root-run file.
	Rules rules.RuleSet `json:"rules"`
	// TCP / UDP are the Docker-published ports the per-port default-deny was
	// scoped to.
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`
	// DNATGuard says whether the script ends DOCKER-USER with the DNAT guard
	// (dnatGuardLines) — true under default_policy=deny.
	DNATGuard bool `json:"dnat_guard"`
}

// Published reports whether port was in the inventory the script was
// compiled against (either protocol).
func (s LiveSnapshot) Published(port int) bool {
	for _, p := range s.TCP {
		if p == port {
			return true
		}
	}
	for _, p := range s.UDP {
		if p == port {
			return true
		}
	}
	return false
}

func liveSnapshotLine(rs rules.RuleSet, pp system.PublishedPorts) string {
	snap := LiveSnapshot{V: 1, Rules: rs, DNATGuard: rs.DefaultPolicy == "deny"}
	snap.Rules.Rules = make([]rules.Rule, len(rs.Rules))
	for i, r := range rs.Rules {
		r.Name, r.Notes = "", ""
		snap.Rules.Rules[i] = r
	}
	snap.TCP, snap.UDP = sortedPorts(pp.TCP), sortedPorts(pp.UDP)
	b, err := json.Marshal(snap)
	if err != nil {
		// Marshalling plain structs cannot fail; if it ever does, an absent
		// record reads as "live state unknown", which is the safe answer.
		return ""
	}
	// encoding/json escapes control characters, so the record is one line
	// and cannot end the comment early.
	return liveSnapshotPrefix + string(b) + "\n"
}

func sortedPorts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for p, ok := range m {
		if ok {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// ErrNoLiveSnapshot is returned by ReadLiveSnapshot for a script that carries
// no record — one compiled by ZFW <= v1.0.26.
var ErrNoLiveSnapshot = errors.New("script carries no zfw-live record")

// ReadLiveSnapshot reads the record from a compiled script (normally the
// engine's applied.sh). The whole script is scanned: the record sits near
// the top, but the scripts are small and a fixed cut-off would be one more
// thing to keep in sync with the emitters.
func ReadLiveSnapshot(path string) (*LiveSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, liveSnapshotPrefix) {
			var s LiveSnapshot
			if err := json.Unmarshal([]byte(strings.TrimPrefix(ln, liveSnapshotPrefix)), &s); err != nil {
				return nil, fmt.Errorf("%s: zfw-live record unreadable: %w", path, err)
			}
			return &s, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, ErrNoLiveSnapshot
}
