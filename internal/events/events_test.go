package events

import (
	"testing"
	"time"
)

// mkEvent is a small constructor so the test bodies stay focused on
// the threat-classifier shape rather than struct literals.
func mkEvent(t time.Time, src string, port int) Event {
	return Event{Time: t, Source: src, Port: port, Protocol: "tcp", Zone: "host"}
}

// hasThreat reports whether e carries the given threat tag. Used by
// every classifier test below.
func hasThreat(e Event, want string) bool {
	for _, got := range e.Threats {
		if got == want {
			return true
		}
	}
	return false
}

// TestClassifyFlagsPortScan locks in the port-scan threshold: a single
// source hitting ≥ portScanPortThreshold distinct dest ports within the
// 1-minute window must carry the `port_scan` tag on (at minimum) the
// event that crossed the threshold.
func TestClassifyFlagsPortScan(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	// portScanPortThreshold distinct dest ports, spread over 30s.
	for i := 0; i < portScanPortThreshold; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 1000+i))
	}
	Classify(events)
	// The threshold-crossing event is the last one; it must be flagged.
	if !hasThreat(events[len(events)-1], "port_scan") {
		t.Fatalf("port_scan not flagged on threshold-crossing event; got %+v", events[len(events)-1])
	}
}

// TestClassifyDoesNotFlagSlowScan guards the window: a probe spread
// across several minutes must NOT trip the port-scan flag — the point
// of the rule is to catch burst behaviour, not slow reconnaissance
// which is a different signal.
func TestClassifyDoesNotFlagSlowScan(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	// portScanPortThreshold distinct ports spread 10 minutes apart.
	for i := 0; i < portScanPortThreshold; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*10*time.Minute), "10.0.0.7", 1000+i))
	}
	Classify(events)
	for _, e := range events {
		if hasThreat(e, "port_scan") {
			t.Fatalf("slow scan falsely flagged as port_scan: %+v", e)
		}
	}
}

// TestClassifyDoesNotFlagBelowThreshold guards the off-by-one: exactly
// portScanPortThreshold-1 distinct ports must NOT trip.
func TestClassifyDoesNotFlagBelowThreshold(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	for i := 0; i < portScanPortThreshold-1; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 1000+i))
	}
	Classify(events)
	for _, e := range events {
		if hasThreat(e, "port_scan") {
			t.Fatalf("sub-threshold scan falsely flagged: %+v", e)
		}
	}
}

// TestClassifyFlagsBruteForce locks in the brute-force threshold: ≥
// bruteForceHitThreshold hits from one source against one bruteForce-
// target port within 60s must carry the `brute_force` tag.
func TestClassifyFlagsBruteForce(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	for i := 0; i < bruteForceHitThreshold; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 22))
	}
	Classify(events)
	if !hasThreat(events[len(events)-1], "brute_force") {
		t.Fatalf("brute_force not flagged on threshold-crossing event; got %+v", events[len(events)-1])
	}
}

// TestClassifyDoesNotBruteForceFlagNonTargetPort guards the target
// filter: hammering an ephemeral port at brute-force volume is a
// different shape (probably a misbehaving client) and must not light
// up the credential-attack banner.
func TestClassifyDoesNotBruteForceFlagNonTargetPort(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	for i := 0; i < bruteForceHitThreshold; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 54321))
	}
	Classify(events)
	for _, e := range events {
		if hasThreat(e, "brute_force") {
			t.Fatalf("brute_force flagged on non-target port: %+v", e)
		}
	}
}

// TestClassifySeparatesSources guards that two sources hitting
// different ports do NOT collapse into one synthetic port-scan — each
// source has its own sliding window.
func TestClassifySeparatesSources(t *testing.T) {
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	events := []Event{}
	// Source A: 5 distinct ports. Source B: 5 distinct ports. Total 10
	// distinct ports but no single source crosses the threshold.
	for i := 0; i < 5; i++ {
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 1000+i))
		events = append(events, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.8", 2000+i))
	}
	Classify(events)
	for _, e := range events {
		if hasThreat(e, "port_scan") {
			t.Fatalf("cross-source false positive: %+v", e)
		}
	}
}

// TestClassifyEmptyIsNoOp guards the trivial case so no nil-slice
// panics ever land in the Read() pipeline.
func TestClassifyEmptyIsNoOp(t *testing.T) {
	got := Classify(nil)
	if got != nil {
		t.Errorf("Classify(nil) = %v, want nil", got)
	}
	got2 := Classify([]Event{})
	if len(got2) != 0 {
		t.Errorf("Classify([]) returned %d events, want 0", len(got2))
	}
}
