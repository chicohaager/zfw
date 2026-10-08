package compiler

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The README and the Events tab promised "Logging is rate-limited to 60/min
// per chain". Nothing in the compiled script does that: xt_limit is not
// shipped on the ZimaOS kernel (measured 2026-05-23: `-m limit` fails with
// "Extension limit revision 0 not supported"), so the LOG lines carry no
// limit match at all — the only volume control is that a LOG sits in front of
// the catch-all DROP and matches --ctstate NEW. This test pins both halves:
// the script carries no time-based limit, and no operator-facing text claims
// one.
func TestNoLogRateLimitIsPromised(t *testing.T) {
	script := Compile(denyRuleSet(), tcpOnly(map[int]bool{8096: true}), nil)
	for _, l := range strings.Split(script, "\n") {
		if strings.Contains(l, "-j LOG") && (strings.Contains(l, "-m limit") || strings.Contains(l, "hashlimit")) {
			t.Fatalf("a LOG line carries a limit match after all — update the docs: %s", l)
		}
	}
	claim := regexp.MustCompile(`(?i)rate[- ]limited to [0-9]+ ?/ ?min|[0-9]+/min per chain`)
	for _, f := range []string{
		"../../README.md", "../../BEST-PRACTICES.md", "../../THREAT-MODEL.md",
		"../../raw/usr/share/casaos/www/modules/zfw/index.html",
		"../../raw/usr/share/casaos/www/modules/zfw/app.js",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := claim.Find(b); m != nil {
			t.Errorf("%s promises a log rate limit the compiled rules do not have: %q", f, m)
		}
	}
}
