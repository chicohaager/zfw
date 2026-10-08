package system

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePublished(t *testing.T) {
	cases := []struct{ in, want string }{
		// IPv4 + IPv6 publishing of one port: one entry
		{"0.0.0.0:8086->80/tcp, :::8086->80/tcp", "[{tcp 8086}]"},
		// bound to one LAN address (the restic-250-server shape)
		{"192.0.2.184:8000->8000/tcp", "[{tcp 8000}]"},
		// loopback only: nothing on the LAN can reach it
		{"127.0.0.1:9000->9000/tcp, [::1]:9000->9000/tcp", "[]"},
		// loopback and LAN for the same port: the LAN binding counts
		{"127.0.0.1:9001->9001/tcp, 0.0.0.0:9001->9001/tcp", "[{tcp 9001}]"},
		{"0.0.0.0:5353->5353/udp", "[{udp 5353}]"},
		{"0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp", "[{tcp 53} {udp 53}]"},
		// exposed but not published, and ranges: no question
		{"80/tcp", "[]"},
		{"0.0.0.0:8000-8002->8000-8002/tcp", "[]"},
		{"", "[]"},
	}
	for _, c := range cases {
		got := fmt.Sprint(parsePublished(c.in))
		if got == "[]" && c.want == "[]" {
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %s, want %s", c.in, got, c.want)
		}
	}
}

func writeCompose(t *testing.T, dir, project, body string) {
	t.Helper()
	p := filepath.Join(dir, project)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "docker-compose.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppTitle(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "casadrop", `name: casadrop
services:
  casadrop:
    image: example/casadrop
    x-casaos:
      title:
        en_us: Not this one (service level)
x-casaos:
  architectures:
    - amd64
  main: casadrop
  title:
    de_de: CasaDrop DE
    en_us: CasaDrop
  index: /
`)
	writeCompose(t, dir, "custom__3vxacvj9", `services:
  site:
    image: example/newt
x-casaos:
  title:
    custom: "Pangolin Site"
`)
	writeCompose(t, dir, "inline", "x-casaos:\n  title: 'Inline App'\n")
	writeCompose(t, dir, "notitle", "x-casaos:\n  main: x\n")
	cases := map[string]string{
		"casadrop":         "CasaDrop",
		"custom__3vxacvj9": "Pangolin Site",
		"inline":           "Inline App",
		"notitle":          "",
		"missing":          "",
		"":                 "",
		"../casadrop":      "", // never leave the apps directory
		"..":               "",
	}
	for project, want := range cases {
		if got := AppTitle(dir, project); got != want {
			t.Errorf("%q: got %q, want %q", project, got, want)
		}
	}
}
