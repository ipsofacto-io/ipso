package importlinter

import "testing"

func TestIdentityLeavesOutTheLineList(t *testing.T) {
	want := "shop.domain -> shop.api"
	for _, line := range []string{"shop.domain -> shop.api (l.1)", "shop.domain -> shop.api (l.40)", "shop.domain -> shop.api (l.1, l.3)"} {
		if got := (Finding{Contract: "layers", Line: line}).identity(); got[0] != "layers" || got[1] != want {
			t.Fatalf("line %q identity %q", line, got)
		}
	}
	if got := (Finding{Contract: "layers", Line: "shop.domain -> shop.infra (l.1)"}).identity(); got[1] == want {
		t.Fatalf("another import shares the identity: %q", got)
	}
}
