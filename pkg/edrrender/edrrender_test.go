package edrrender

import (
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/pkg/edrcheck"
)

func TestRenderedFilesPassEdrcheck(t *testing.T) {
	id := ID([16]byte{0x01, 0x93, 0x4a, 0x9c, 0x11, 0x22, 0x70, 0x01, 0x80, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	end := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, d := range map[string]Decision{
		"full":    {ID: id, Body: []byte(`{"slug":"use-tls","title":"Use TLS","status":"accepted","statement":"Use TLS."}`), ValidFrom: time.Now()},
		"seed":    {ID: id, Body: []byte(`{"premises":[{"id":"tls-version"}]}`), ValidFrom: time.Now()},
		"history": {ID: id, Body: []byte(`{}`), ValidFrom: time.Now().AddDate(-1, 0, 0), ValidTo: &end},
	} {
		text, err := Render(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if problems := edrcheck.Validate(text); len(problems) > 0 {
			t.Fatalf("%s: %s\n%s", name, strings.Join(problems, "; "), text)
		}
	}
}

func TestRenderRefusesABadID(t *testing.T) {
	if _, err := Render(Decision{ID: "x", ValidFrom: time.Now()}); err == nil {
		t.Fatal("bad id accepted")
	}
}
