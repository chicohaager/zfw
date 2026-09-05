package conntrack

import (
	"context"
	"strings"
	"testing"
)

// TestParseLineProcShape guards the /proc/net/nf_conntrack line
// format (the production source). The "ipv4 2" L3 prefix must be
// stripped transparently so downstream parsing sees the same shape
// as conntrack(8) output.
func TestParseLineProcShape(t *testing.T) {
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=33124 dport=22 src=10.0.0.2 dst=10.0.0.1 sport=22 dport=33124 [ASSURED] mark=0"
	e, ok := parseLine(line)
	if !ok {
		t.Fatal("parseLine returned ok=false on a /proc-shaped TCP line")
	}
	if e.Protocol != "tcp" || e.State != "ESTABLISHED" {
		t.Errorf("Protocol/State = %q/%q, want tcp/ESTABLISHED", e.Protocol, e.State)
	}
	if e.SrcIP != "10.0.0.1" || e.DstPort != 22 || e.AgeSec != 431999 {
		t.Errorf("/proc-shape line parsed wrong: %+v", e)
	}
}

// TestParseLineEstablishedTCP guards the canonical happy path: a
// kernel-emitted TCP ESTABLISHED line must parse into an Entry with
// the original-direction src/dst (not the reply direction) and the
// ESTABLISHED state.
func TestParseLineEstablishedTCP(t *testing.T) {
	line := "tcp      6 431999 ESTABLISHED src=192.168.1.42 dst=192.168.1.100 sport=33124 dport=22 src=192.168.1.100 dst=192.168.1.42 sport=22 dport=33124 [ASSURED] mark=0 zone=0 use=1"
	e, ok := parseLine(line)
	if !ok {
		t.Fatal("parseLine returned ok=false on a valid TCP line")
	}
	if e.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", e.Protocol)
	}
	if e.State != "ESTABLISHED" {
		t.Errorf("State = %q, want ESTABLISHED", e.State)
	}
	if e.SrcIP != "192.168.1.42" || e.DstIP != "192.168.1.100" {
		t.Errorf("Src/Dst = %s→%s, want 192.168.1.42→192.168.1.100 (original direction)", e.SrcIP, e.DstIP)
	}
	if e.SrcPort != 33124 || e.DstPort != 22 {
		t.Errorf("Ports = %d→%d, want 33124→22", e.SrcPort, e.DstPort)
	}
	if e.AgeSec != 431999 {
		t.Errorf("AgeSec = %d, want 431999", e.AgeSec)
	}
}

// TestParseLineUDPStateless guards stateless protocols: a UDP line
// has no state name. State must stay empty (omitempty in JSON), the
// rest of the fields populate normally.
func TestParseLineUDPStateless(t *testing.T) {
	line := "udp      17 29 src=192.168.1.50 dst=224.0.0.251 sport=5353 dport=5353 src=224.0.0.251 dst=192.168.1.50 sport=5353 dport=5353 mark=0 zone=0 use=1"
	e, ok := parseLine(line)
	if !ok {
		t.Fatal("parseLine returned ok=false on a valid UDP line")
	}
	if e.Protocol != "udp" {
		t.Errorf("Protocol = %q, want udp", e.Protocol)
	}
	if e.State != "" {
		t.Errorf("State = %q, want empty (UDP is stateless)", e.State)
	}
	if e.SrcPort != 5353 || e.DstPort != 5353 {
		t.Errorf("Ports = %d→%d, want 5353→5353", e.SrcPort, e.DstPort)
	}
}

// TestParseLineRejectsMissingEndpoint guards the malformed-input
// safety net: a line without src/dst (kernel emits these
// transiently during connection setup for some L4 protos) must be
// dropped rather than emitted as an Entry with empty IPs.
func TestParseLineRejectsMissingEndpoint(t *testing.T) {
	line := "unknown 254 60 mark=0 zone=0 use=1"
	_, ok := parseLine(line)
	if ok {
		t.Fatal("parseLine accepted a line with no src=/dst=, want false")
	}
}

// TestParseLineFlagsDontOverwriteState guards a parser foot-gun:
// flag tokens like [ASSURED] appear AFTER the state name in many
// kernels but appear as bare tokens with brackets stripped in
// /proc output. State must remain the first state-shaped token seen.
func TestParseLineFlagsDontOverwriteState(t *testing.T) {
	line := "tcp      6 100 TIME_WAIT src=10.0.0.1 dst=10.0.0.2 sport=4242 dport=80 ASSURED UNREPLIED mark=0"
	e, ok := parseLine(line)
	if !ok {
		t.Fatal("parseLine returned ok=false")
	}
	if e.State != "TIME_WAIT" {
		t.Errorf("State = %q, want TIME_WAIT (must NOT be overwritten by trailing flag)", e.State)
	}
}

// TestParseStreamSkipsGarbageLines guards stream-level resilience: a
// mixed stream of valid and garbage lines must yield only the valid
// entries. The parser must never error on a malformed line.
func TestParseStreamSkipsGarbageLines(t *testing.T) {
	stream := strings.NewReader(`tcp      6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=11111 dport=80 src=5.6.7.8 dst=1.2.3.4 sport=80 dport=11111 mark=0
# kernel comment, not an entry
this line is not a conntrack record
udp      17 29 src=10.0.0.1 dst=10.0.0.2 sport=5353 dport=5353 mark=0
`)
	out, err := parseStream(context.Background(), stream, 0)
	if err != nil {
		t.Fatalf("parseStream: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2 (one TCP, one UDP)", len(out))
	}
	if out[0].Protocol != "tcp" || out[1].Protocol != "udp" {
		t.Errorf("entry order/proto wrong: %+v", out)
	}
}

// TestParseStreamHonoursLimit guards the bounded-output contract: a
// limit < the entry count must stop the scan at limit, limit==0 must
// return everything.
func TestParseStreamHonoursLimit(t *testing.T) {
	const line = "tcp      6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=11111 dport=80 src=5.6.7.8 dst=1.2.3.4 sport=80 dport=11111 mark=0\n"
	input := strings.Repeat(line, 5)
	got, err := parseStream(context.Background(), strings.NewReader(input), 2)
	if err != nil {
		t.Fatalf("parseStream: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("limit=2 returned %d entries, want 2", len(got))
	}
	got, err = parseStream(context.Background(), strings.NewReader(input), 0)
	if err != nil {
		t.Fatalf("parseStream: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("limit=0 returned %d entries, want all 5", len(got))
	}
	got, err = parseStream(context.Background(), strings.NewReader(input), 100)
	if err != nil {
		t.Fatalf("parseStream: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("limit=100 returned %d entries, want all 5", len(got))
	}
}
