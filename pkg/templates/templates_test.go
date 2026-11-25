package templates

import (
	"slices"
	"strings"
	"testing"
)

func TestListHoldsBothCatalogs(t *testing.T) {
	list := List()
	if len(list) != 30 {
		t.Fatalf("%d templates, want 20 plan and 10 Semgrep", len(list))
	}
	var plan, semgrep int
	for i, entry := range list {
		if i > 0 && list[i-1].ID >= entry.ID {
			t.Fatalf("not sorted at %s", entry.ID)
		}
		if entry.Ref != "ipso:"+entry.ID || entry.Title == "" {
			t.Fatalf("entry %#v", entry)
		}
		switch {
		case entry.Engine == "opa" && entry.Target == "terraform-plan" && len(entry.Resources) > 0 && len(entry.Languages) == 0:
			plan++
		case entry.Engine == "semgrep" && entry.Target == "" && len(entry.Languages) > 0 && len(entry.Resources) == 0:
			semgrep++
		default:
			t.Fatalf("entry %#v", entry)
		}
	}
	if plan != 20 || semgrep != 10 {
		t.Fatalf("plan %d semgrep %d", plan, semgrep)
	}
}

func TestLookup(t *testing.T) {
	got, ok := Lookup("ipso:aws/ebs-encrypted")
	if !ok || got.Engine != "opa" || got.Target != "terraform-plan" || !slices.Contains(got.Resources, "aws_ebs_volume") {
		t.Fatalf("aws/ebs-encrypted %#v %v", got, ok)
	}
	got, ok = Lookup("ipso:go/use-slog")
	if !ok || got.Engine != "semgrep" || got.Target != "" || !slices.Equal(got.Languages, []string{"go"}) {
		t.Fatalf("go/use-slog %#v %v", got, ok)
	}
	for _, ref := range []string{"", "aws/ebs-encrypted", "ipso:", "ipso:lib/terraform", "ipso:aws/ebs-encrypted ", "IPSO:aws/ebs-encrypted", "ipso:aws/unknown", "ipso:aws/../aws/ebs-encrypted"} {
		if _, ok := Lookup(ref); ok {
			t.Errorf("Lookup(%q) found a template", ref)
		}
	}
}

func TestCallerCannotChangeTheCatalog(t *testing.T) {
	list := List()
	list[0].Title = "changed"
	list[0].Resources = append(list[0].Resources[:0], "changed")
	got, _ := Lookup(list[0].Ref)
	if got.Title == "changed" || strings.Contains(strings.Join(got.Resources, ","), "changed") {
		t.Fatalf("catalog changed: %#v", got)
	}
}
