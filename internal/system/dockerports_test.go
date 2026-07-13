package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func fakeBin(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestDockerPortsWithoutUserlandProxy is the regression guard for the missing
// DOCKER-USER default-deny reported on v1.0.16. The deny is emitted once per
// published port, so an empty inventory means no deny at all — the firewall
// fails open while the dashboard stays green.
//
// Before v1.0.17 the inventory came solely from docker-proxy listening
// sockets. A daemon running with "userland-proxy": false has no such process,
// so `ss` shows nothing and every published port lost its default-deny.
func TestDockerPortsWithoutUserlandProxy(t *testing.T) {
	dir := t.TempDir()
	// No docker-proxy anywhere in `ss` output — the DNAT-only host.
	fakeBin(t, dir, "ss", `echo 'LISTEN 0 4096 127.0.0.1:8489 0.0.0.0:* users:(("zfwd",pid=1,fd=9))'`)
	fakeBin(t, dir, "docker", `echo 'abc123	web	nginx	0.0.0.0:8086->8080/tcp, :::8086->8080/tcp'`)
	t.Setenv("PATH", dir)

	got, err := DockerPorts(context.Background())
	if err != nil {
		t.Fatalf("DockerPorts err = %v, want nil (both sources readable)", err)
	}
	if !got.TCP[8086] {
		t.Fatalf("DockerPorts = %v, want port 8086 from `docker ps`; without it the "+
			"DOCKER-USER default-deny is silently not emitted", got)
	}
}

// TestDockerPortsUnionsBothInventories: docker-proxy and `docker ps` each know
// ports the other may miss, so the result is their union, not either alone.
func TestDockerPortsUnionsBothInventories(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "ss", `echo 'LISTEN 0 0 0.0.0.0:3009 0.0.0.0:* users:(("docker-proxy",pid=11170,fd=7))'`)
	fakeBin(t, dir, "docker", `echo 'abc123	web	nginx	0.0.0.0:8086->8080/tcp'`)
	t.Setenv("PATH", dir)

	got, err := DockerPorts(context.Background())
	if err != nil {
		t.Fatalf("DockerPorts err = %v, want nil (both sources readable)", err)
	}
	for _, p := range []int{3009, 8086} {
		if !got.TCP[p] {
			t.Errorf("DockerPorts = %v, missing port %d", got, p)
		}
	}
}

// TestDockerPortsDockerDown: `docker ps` failing must not lose the ports that
// docker-proxy still proves are published — but it must report the inventory as
// incomplete. The ports it *did* find are a floor, not the truth: the UDP half
// is invisible to a socket scan, so scoping a default-deny by this set alone
// would leave every published UDP port reachable from any source.
func TestDockerPortsDockerDown(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "ss", `echo 'LISTEN 0 0 0.0.0.0:3009 0.0.0.0:* users:(("docker-proxy",pid=11170,fd=7))'`)
	fakeBin(t, dir, "docker", `echo "Cannot connect to the Docker daemon" >&2; exit 1`)
	t.Setenv("PATH", dir)

	got, err := DockerPorts(context.Background())
	if err == nil {
		t.Fatal("DockerPorts err = nil with `docker ps` down — an unreadable inventory must " +
			"be reported, not silently returned as a short port list")
	}
	if got.SourceErr == nil {
		t.Error("PublishedPorts.SourceErr = nil, want the inventory to carry its own health")
	}
	if !got.TCP[3009] || len(got.All()) != 1 {
		t.Errorf("DockerPorts = %v, want exactly {3009} preserved", got)
	}
}

// TestDockerPortsDockerlessHost: no docker CLI and no docker-proxy listener is a
// host that simply does not run Docker. There is no DOCKER-USER chain to scope,
// so the empty inventory is the truth and must not block the host rules from
// compiling.
func TestDockerPortsDockerlessHost(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "ss", `echo 'LISTEN 0 4096 127.0.0.1:8489 0.0.0.0:* users:(("zfwd",pid=1,fd=9))'`)
	t.Setenv("PATH", dir) // no `docker` binary at all

	got, err := DockerPorts(context.Background())
	if err != nil {
		t.Fatalf("DockerPorts err = %v on a docker-less host, want nil", err)
	}
	if got.Any() {
		t.Errorf("DockerPorts = %v, want empty", got)
	}
}

// TestDockerPortsDaemonDownIsNotEmpty is the regression guard for the field
// report against v1.0.19: DOCKER-USER came out with zero `ctorigdstport` rules
// while the apply reported success. The daemon could not read its docker
// inventory, the empty result was taken for "nothing is published", and the
// per-port default-deny was therefore never emitted. An unreadable inventory
// must be distinguishable from an empty one — that distinction is what lets
// the compile refuse instead of shipping an open forward path.
func TestDockerPortsDaemonDownIsNotEmpty(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "ss", `echo ''`)
	fakeBin(t, dir, "docker", `echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1`)
	t.Setenv("PATH", dir)

	got, err := DockerPorts(context.Background())
	if err == nil {
		t.Fatal("DockerPorts err = nil while the docker daemon is unreachable — " +
			"the empty inventory would be read as \"nothing to protect\" and " +
			"DOCKER-USER would be emitted without a single deny rule")
	}
	if got.Any() {
		t.Errorf("DockerPorts = %v, want empty", got)
	}
}

// TestParseDockerPortsSplitsProtocols pins the UDP half of the inventory.
// A bare "32400/udp" (no "->") is a container-internal port, not published.
func TestParseDockerPortsSplitsProtocols(t *testing.T) {
	tcp, udp := parseDockerPorts(
		"0.0.0.0:8181->80/tcp, :::8181->80/tcp, 0.0.0.0:8181->80/udp, 0.0.0.0:8086->8080/tcp, 32400/udp")

	if want := []int{8086, 8181}; !equalInts(tcp, want) {
		t.Errorf("tcp = %v, want %v", tcp, want)
	}
	if want := []int{8181}; !equalInts(udp, want) {
		t.Errorf("udp = %v, want %v (a bare 32400/udp is not published)", udp, want)
	}
}

// TestDockerPortsPicksUpUDP: the union inventory must carry UDP through to the
// caller that scopes the default-deny.
func TestDockerPortsPicksUpUDP(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "ss", `echo ''`)
	fakeBin(t, dir, "docker", `echo 'abc123	web	nginx	0.0.0.0:8181->80/tcp, 0.0.0.0:8181->80/udp'`)
	t.Setenv("PATH", dir)

	got, err := DockerPorts(context.Background())
	if err != nil {
		t.Fatalf("DockerPorts err = %v, want nil", err)
	}
	if !got.TCP[8181] || !got.UDP[8181] {
		t.Fatalf("DockerPorts = %+v, want 8181 on both protocols", got)
	}
	if !got.Has(8181) || !got.Any() {
		t.Error("Has/Any must see the published port")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
