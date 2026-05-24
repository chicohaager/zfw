package system

import (
	"reflect"
	"testing"
)

// TestParseDockerPorts covers the documented input shapes for the
// docker-ps Ports column. Only host-mapped TCP entries with the
// "host:port->container/tcp" form should produce a port; UDP and
// container-only entries are dropped.
func TestParseDockerPorts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []int
	}{
		{
			"empty",
			"",
			nil,
		},
		{
			"dual-stack jellyfin shape",
			"0.0.0.0:8096->8096/tcp, :::8096->8096/tcp",
			[]int{8096},
		},
		{
			"mixed tcp + udp drops udp",
			"0.0.0.0:32400->32400/tcp, :::32400->32400/tcp, 32400/udp",
			[]int{32400},
		},
		{
			"container-only port skipped",
			"6379/tcp",
			nil,
		},
		{
			"udp-only mapping dropped",
			"0.0.0.0:53->53/udp",
			nil,
		},
		{
			"different host vs container port — host wins",
			"0.0.0.0:8888->80/tcp",
			[]int{8888},
		},
		{
			"out-of-range port dropped",
			"0.0.0.0:65536->80/tcp, 0.0.0.0:0->80/tcp",
			nil,
		},
		{
			"two distinct ports sorted",
			"0.0.0.0:8443->443/tcp, 0.0.0.0:8080->80/tcp",
			[]int{8080, 8443},
		},
		{
			"dup-port collapses",
			"0.0.0.0:9000->9000/tcp, :::9000->9000/tcp, 0.0.0.0:9000->9000/tcp",
			[]int{9000},
		},
		{
			"malformed entry skipped",
			"garbage, 0.0.0.0:5050->80/tcp, no-arrow/tcp",
			[]int{5050},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseDockerPorts(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseDockerPorts(%q)=%v want %v", c.in, got, c.want)
			}
		})
	}
}

// TestExtractVersion pins the version-banner parser for the Versions
// tab. The banner shape drifts every few releases of the underlying
// tools so a test here catches a silent "Versions tab shows blank"
// regression.
func TestExtractVersion(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"docker", "Docker version 27.5.1, build a187fa5\n", "27.5.1"},
		{"iptables-legacy", "iptables v1.8.10 (legacy)", "1.8.10"},
		{"iptables-no-leading-v", "iptables 1.8.7", "1.8.7"},
		{"empty", "", ""},
		{"no version", "no version here at all", ""},
		{"trim trailing comma", "Foo version 1.2.3,", "1.2.3"},
		{"keep dotted only", "v3.0.0-rc1", "3.0.0-rc1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractVersion(c.in); got != c.want {
				t.Errorf("extractVersion(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

// TestOpensshVersion covers the ssh -V banner: "OpenSSH_X.Yp1, OpenSSL ..."
func TestOpensshVersion(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"standard banner", "OpenSSH_9.9p2, OpenSSL 3.4.3 5 Mar 2025\n", "9.9p2"},
		// No "OpenSSH_" prefix → the function strips at the first
		// space/comma; "ssh: garbled output" becomes "ssh:" (degraded
		// but stable behaviour the UI handles).
		{"no openssh prefix", "ssh: garbled output", "ssh:"},
		{"empty", "", ""},
		{"trailing newline stripped", "OpenSSH_9.8p1 some other text", "9.8p1"},
		{"version only", "OpenSSH_8.4p1", "8.4p1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opensshVersion(c.in); got != c.want {
				t.Errorf("opensshVersion(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

// TestParseKernel covers the major.minor.patch splitter shared by
// kernelVulnerable and dockerOld.
func TestParseKernel(t *testing.T) {
	cases := []struct {
		in    string
		maj   int
		min   int
		patch int
	}{
		{"6.12.30-zima", 6, 12, 30},
		{"6.12.86", 6, 12, 86},
		{"6.1.0", 6, 1, 0},
		{"5.15", 5, 15, 0},
		{"6", 6, 0, 0},
		{"", 0, 0, 0},
		{"garbage", 0, 0, 0},
		{"6.x.y", 6, 0, 0},
	}
	for _, c := range cases {
		maj, min, patch := parseKernel(c.in)
		if maj != c.maj || min != c.min || patch != c.patch {
			t.Errorf("parseKernel(%q)=(%d,%d,%d) want (%d,%d,%d)",
				c.in, maj, min, patch, c.maj, c.min, c.patch)
		}
	}
}

// TestKernelVulnerable pins the CVE-2026-31431 (Copy Fail) detection
// window: 6.12.[1..85] is vulnerable; everything outside is "ok".
func TestKernelVulnerable(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"6.12.30", true},  // smack in the middle
		{"6.12.85", true},  // last vulnerable
		{"6.12.86", false}, // fix landed here
		{"6.12.99", false},
		{"6.12.0", false}, // 0 is "not patch >0"
		{"6.11.99", false},
		{"6.13.0", false},
		{"5.15.0", false},
		{"7.0.0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := kernelVulnerable(c.in); got != c.want {
			t.Errorf("kernelVulnerable(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

// TestDockerOld pins the docker cp escapes detection: < 29 is old.
func TestDockerOld(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"27.5.1", true},
		{"28.99.99", true},
		{"29.0.0", false},
		{"29.3.1", false},
		{"30.0.0", false},
		{"", false}, // unknown — don't trip the warning
	}
	for _, c := range cases {
		if got := dockerOld(c.in); got != c.want {
			t.Errorf("dockerOld(%q)=%v want %v", c.in, got, c.want)
		}
	}
}
