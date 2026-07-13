package handlers

import (
	"reflect"
	"testing"

	"github.com/chicohaager/zfw/internal/system"
)

// TestContainerPortsUnionsUDP is the regression guard for the container-binding
// UDP blind spot.
//
// A rule bound to a container has its port list rewritten from the live docker
// inventory on every recompile — the UI's promise is that the rule "follows its
// container". The substitution keyed on DockerContainer.Ports alone, which is
// the TCP list: a container publishing 8181/tcp + 5514/udp had its bound rule
// rewritten to just [8181], so the UDP port lost the allow rule it was supposed
// to have and was silently dropped by the default-deny. Same UDP blind spot
// v1.0.17 closed in the port inventory itself, one layer up.
func TestContainerPortsUnionsUDP(t *testing.T) {
	got := containerPorts(system.DockerContainer{
		ID: "abc", Name: "syslog",
		Ports:    []int{8181},
		PortsUDP: []int{5514},
	})
	want := []int{5514, 8181}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containerPorts = %v, want %v — a bound container's UDP ports must "+
			"survive the substitution, or its own allow rule silently stops "+
			"covering them", got, want)
	}
}

// TestContainerPortsDeduplicatesAcrossProtocols: a container publishing the same
// host port on both protocols (8181/tcp + 8181/udp) must yield that port once.
// The list is a port *set*; the rule's Protocol field decides which protocols
// the ports are emitted for.
func TestContainerPortsDeduplicatesAcrossProtocols(t *testing.T) {
	got := containerPorts(system.DockerContainer{
		Ports:    []int{8181, 9000},
		PortsUDP: []int{8181},
	})
	want := []int{8181, 9000}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containerPorts = %v, want %v (deduplicated)", got, want)
	}
}

// TestContainerPortsTCPOnlyIsUnchanged: the common case — no UDP mappings — must
// pass the already-sorted TCP list straight through.
func TestContainerPortsTCPOnlyIsUnchanged(t *testing.T) {
	got := containerPorts(system.DockerContainer{Ports: []int{80, 443}})
	want := []int{80, 443}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containerPorts = %v, want %v", got, want)
	}
}
