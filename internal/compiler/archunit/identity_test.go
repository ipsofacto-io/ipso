package archunit

import "testing"

func TestIdentityLeavesOutTheSourceLine(t *testing.T) {
	first := Finding{Rule: "r", Line: "Method <a.A.m()> calls method <b.B.n()> in (A.java:3)"}.identity()
	moved := Finding{Rule: "r", Line: "Method <a.A.m()> calls method <b.B.n()> in (A.java:40)"}.identity()
	other := Finding{Rule: "r", Line: "Method <a.A.m()> calls method <b.B.n()> in (B.java:3)"}.identity()
	if first[1] != moved[1] || first[1] == other[1] {
		t.Fatalf("first %q moved %q other %q", first, moved, other)
	}
	if first[1] != "Method <a.A.m()> calls method <b.B.n()> in (A.java)" {
		t.Fatalf("identity %q", first[1])
	}
}
