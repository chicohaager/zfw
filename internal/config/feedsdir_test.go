package config

import (
	"os"
	"regexp"
	"testing"
)

// The feed cache directory is named in the operator docs; an operator looking
// for the .ipset files on a host goes there. Pin the docs to the default the
// daemon actually uses (ZFW_FEEDS unset — the shipped zfw-ui.service sets no
// ZFW_FEEDS), so the two cannot drift apart silently.
func TestDocsNameTheRealFeedsDir(t *testing.T) {
	t.Setenv("ZFW_FEEDS", "")
	os.Unsetenv("ZFW_FEEDS")
	def := Load().FeedsDir
	if def != "/DATA/zfw/feeds" {
		t.Fatalf("default FeedsDir = %q — update the docs together with it", def)
	}
	re := regexp.MustCompile("/DATA/[A-Za-z0-9_/]*feeds")
	checked := 0
	for _, f := range []string{"../../README.md", "../../BEST-PRACTICES.md", "../../THREAT-MODEL.md", "../../docs/openapi.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllString(string(b), -1) {
			checked++
			if m != def {
				t.Errorf("%s names feed dir %q, daemon default is %q", f, m, def)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no feed directory mention found in the docs — the test checks nothing")
	}
	unit, err := os.ReadFile("../../raw/usr/lib/systemd/system/zfw-ui.service")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^Environment=ZFW_FEEDS=`).Match(unit) {
		t.Error("zfw-ui.service overrides ZFW_FEEDS — the docs then describe the wrong directory")
	}
}
