package firewall

import "testing"

// Shape of `iptables -L ZFW-IN -v -n -x`: header, column line, then rules
// with exact (-x) pkts/bytes in the first two columns.
const countersDump = `Chain ZFW-IN (1 references)
    pkts      bytes target     prot opt in     out     source               destination
   40213  2411520 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
     609    36540 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set zfw-feed-spamhaus_drop src
      12      720 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set zfw-feed-spamhaus_drop src tcp dpt:443
       7      420 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set zfw-feed-spamhaus_dropx src
       3      180 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set zfw-cc-ru src
`

func TestSumMatchSetAddsOnlyExactSetLines(t *testing.T) {
	p, b := sumMatchSet(countersDump, "zfw-feed-spamhaus_drop")
	if p != 621 || b != 37260 {
		t.Fatalf("pkts=%d bytes=%d, want 621 / 37260 (two lines; the -dropx set and the country set must not count)", p, b)
	}
	if p, b := sumMatchSet(countersDump, "zfw-feed-firehol_level1"); p != 0 || b != 0 {
		t.Fatalf("absent set counted %d/%d", p, b)
	}
	if p, _ := sumMatchSet("", "zfw-feed-spamhaus_drop"); p != 0 {
		t.Fatal("empty dump counted")
	}
}
