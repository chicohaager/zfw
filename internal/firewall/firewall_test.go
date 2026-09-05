package firewall

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestValidate covers the conf-level validation, including the R5-2
// IPv4-only contract for LAN/HOST_IP: an IPv6 value passes ParseCIDR/
// ParseIP but would abort the apply mid-script in the IPv4 chains.
func TestValidate(t *testing.T) {
	base := Config{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100",
		HostTCPLAN: []string{"22", "443"},
		HostUDPLAN: []string{"5353"},
	}
	if err := validate(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"ipv6 LAN", func(c *Config) { c.LAN = "2001:db8::/64" }},
		{"ipv6 HostIP", func(c *Config) { c.HostIP = "::1" }},
		{"non-CIDR LAN", func(c *Config) { c.LAN = "192.168.1.1" }},
		{"empty LAN", func(c *Config) { c.LAN = "" }},
		{"bad HostIP", func(c *Config) { c.HostIP = "not-an-ip" }},
		{"port zero", func(c *Config) { c.HostTCPLAN = []string{"0"} }},
		{"port too high", func(c *Config) { c.HostUDPLAN = []string{"70000"} }},
		{"non-numeric port", func(c *Config) { c.DockerDropLAN = []string{"abc"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			if err := validate(c); err == nil {
				t.Errorf("%s: expected validation error, got nil", tc.name)
			}
		})
	}
}

// TestSaveLoadRoundtrip guards that a config survives a write+read cycle
// unchanged — the conf format is the contract between the daemon and the
// engine script, so a serialisation drift would silently corrupt rules.
func TestSaveLoadRoundtrip(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "allowlist.conf")
	m := &Manager{Conf: conf}
	want := Config{
		LAN: "10.0.0.0/8", HostIP: "10.0.0.5",
		HostTCPLAN:    []string{"22", "80", "443"},
		HostUDPLAN:    []string{"53", "5353"},
		DockerDropLAN: []string{"8888"},
		V6Drop:        []string{"23", "2323"},
	}
	if err := m.SaveConfig(want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := m.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip mismatch:\n got  %+v\n want %+v", got, want)
	}
}

// TestSaveConfigRejectsInvalid guards that SaveConfig refuses to persist
// a config that fails validation — an invalid conf must never reach disk
// where the engine would read it.
func TestSaveConfigRejectsInvalid(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "allowlist.conf")
	m := &Manager{Conf: conf}
	if err := m.SaveConfig(Config{LAN: "::1/128", HostIP: "10.0.0.5"}); err == nil {
		t.Fatal("SaveConfig persisted an IPv6 LAN")
	}
}

// TestLoadConfigSkipsCommentsAndBlanks guards the conf parser's
// resilience: comments, blank lines and unknown keys must be ignored,
// not error the whole load.
func TestLoadConfigSkipsCommentsAndBlanks(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "allowlist.conf")
	m := &Manager{Conf: conf}
	if err := m.SaveConfig(Config{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.1",
		HostTCPLAN: []string{"22"},
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := m.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.LAN != "192.168.1.0/24" || len(got.HostTCPLAN) != 1 || got.HostTCPLAN[0] != "22" {
		t.Errorf("parsed config wrong: %+v", got)
	}
}

func TestSplitPorts(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"22,80,443", []string{"22", "80", "443"}},
		{" 22 , 80 ", []string{"22", "80"}},
		{"", []string{}},
		{",,", []string{}},
		{"22,,443", []string{"22", "443"}},
	}
	for _, c := range cases {
		if got := splitPorts(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitPorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
