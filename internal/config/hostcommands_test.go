package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// On a stock ZimaOS the login user is not in the docker group — measured on a
// v1.7.1 host on 2026-08-25: groups `samba wheel`, every docker call
// "permission denied" — and the installer and the engine refuse to run as
// anyone but root (install.sh preflight, engine paths under /DATA/zfw are
// root:root 0700). A command in the docs that an operator copies onto the host
// without sudo therefore fails. Every such command must carry it.
func TestHostCommandsInDocsUseSudo(t *testing.T) {
	hostCmd := regexp.MustCompile(`docker run [^\n]*(chicohaager/zfw|<image>)|(^|[\s'"&;])sh install\.sh|/DATA/zfw/zfw (revert|commit|status|apply)`)
	checked := 0
	for _, f := range []string{
		"../../README.md", "../../BEST-PRACTICES.md", "../../MOD-STORE.md",
		"../../Dockerfile", "../../docker-entrypoint.sh", "../../install.sh", "../../engine/zfw",
		"../../raw/usr/share/casaos/www/modules/zfw/index.html",
		"../../raw/usr/share/casaos/www/modules/zfw/app.js",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !hostCmd.MatchString(line) {
				continue
			}
			checked++
			if !strings.Contains(line, "sudo") {
				t.Errorf("%s:%d: host command without sudo: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no host command found — the pattern matches nothing and checks nothing")
	}
}
