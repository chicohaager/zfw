package rules

import "testing"

// TestTemplatesAllValid guards the catalog: every Rule emitted by any
// Template must pass Validate. If a contributor adds a new template
// with a broken Source / Ports / Protocol / Zone the test goes red
// before the bad rules can reach a user's rule set.
func TestTemplatesAllValid(t *testing.T) {
	for _, lan := range []string{"192.168.1.0/24", ""} {
		tmpls := Templates(lan)
		if len(tmpls) == 0 {
			t.Fatalf("Templates(%q) returned empty catalog", lan)
		}
		for _, tmpl := range tmpls {
			rs := RuleSet{DefaultPolicy: "deny", Rules: tmpl.Rules}
			if err := Validate(rs); err != nil {
				t.Errorf("template %q produces invalid rules (lan=%q): %v",
					tmpl.ID, lan, err)
			}
			if tmpl.ID == "" || tmpl.Name == "" || tmpl.Description == "" {
				t.Errorf("template %q has empty metadata", tmpl.ID)
			}
		}
	}
}

// TestTemplatesFreshIDs locks in that two consecutive Templates() calls
// hand back distinct Rule.IDs — otherwise a user adding the same
// template twice would get duplicate IDs and the frontend's
// ruleAction(id, …) lookup would target the wrong row.
func TestTemplatesFreshIDs(t *testing.T) {
	a := Templates("192.168.1.0/24")
	b := Templates("192.168.1.0/24")
	if len(a) != len(b) {
		t.Fatalf("Templates() returned inconsistent lengths: %d vs %d", len(a), len(b))
	}
	for i := range a {
		for j, ar := range a[i].Rules {
			br := b[i].Rules[j]
			if ar.ID == br.ID {
				t.Errorf("template %q rule %d: ID %q reused across calls",
					a[i].ID, j, ar.ID)
			}
		}
	}
}

// TestTemplatesSubstituteLAN checks that the "Allow Plex" template picks
// up the caller's LAN CIDR — and falls back to source.type "any" when
// no LAN is known (rather than emitting a half-formed range source).
func TestTemplatesSubstituteLAN(t *testing.T) {
	withLAN := Templates("10.0.0.0/24")
	plex := findTemplate(t, withLAN, "allow-plex")
	if plex.Rules[0].Source.Type != "range" || plex.Rules[0].Source.Value != "10.0.0.0/24" {
		t.Errorf("allow-plex source = %+v, want range/10.0.0.0/24",
			plex.Rules[0].Source)
	}
	noLAN := Templates("")
	plex2 := findTemplate(t, noLAN, "allow-plex")
	if plex2.Rules[0].Source.Type != "any" {
		t.Errorf("allow-plex with empty LAN: source.type = %q, want any",
			plex2.Rules[0].Source.Type)
	}
}

func findTemplate(t *testing.T, tmpls []Template, id string) Template {
	t.Helper()
	for _, x := range tmpls {
		if x.ID == id {
			return x
		}
	}
	t.Fatalf("template %q not found in catalog", id)
	return Template{}
}
