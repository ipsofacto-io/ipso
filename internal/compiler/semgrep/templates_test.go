package semgrep

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler/compilertest"
)

// Fixtures end in .fixture so CodeQL and the org Semgrep scan do not treat the deliberate violations as source.
func TestTemplates(t *testing.T) {
	ids := templateIDs()
	if strings.Join(ids, "\n") != strings.Join(wantTemplateIDs, "\n") {
		t.Fatalf("templates\n%s\nwant\n%s", strings.Join(ids, "\n"), strings.Join(wantTemplateIDs, "\n"))
	}
	rows := make([]Template, 0, len(ids))
	required := map[string]struct{}{}
	for _, id := range ids {
		src, ok := lookup(id)
		if !ok {
			t.Fatalf("missing template %s", id)
		}
		if _, err := compileConfig(src, "block"); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		row, err := readTemplate(id, src)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		rows = append(rows, row)
		ruleID := strings.ReplaceAll(id, "/", ".")
		dir, name, _ := strings.Cut(id, "/")
		for _, language := range row.Languages {
			ext, known := languageExt[language]
			if !known {
				t.Fatalf("%s: no fixture extension for %s", id, language)
			}
			rel := filepath.ToSlash(filepath.Join("testdata", "fixtures", dir, name+"."+ext+".fixture"))
			required[rel] = struct{}{}
			body, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("%s: %v", rel, err)
			}
			text := string(body)
			if !strings.Contains(text, "ruleid: "+ruleID) || !strings.Contains(text, "ok: "+ruleID) {
				t.Errorf("%s: want ruleid and ok for %s", rel, ruleID)
			}
		}
	}
	checkOrphans(t, required)
	checkDoc(t, rows)
}

func TestTemplatesCatalog(t *testing.T) {
	got := Templates()
	if len(got) != len(wantTemplateIDs) {
		t.Fatalf("catalog has %d templates, want %d", len(got), len(wantTemplateIDs))
	}
	for i, entry := range got {
		if entry.ID != wantTemplateIDs[i] || entry.Title == "" || len(entry.Languages) == 0 {
			t.Fatalf("entry %d %#v", i, entry)
		}
	}
	got[0].Languages[0] = "changed"
	if Templates()[0].Languages[0] == "changed" {
		t.Fatal("Templates shares its slices with the caller")
	}
}

func checkOrphans(t *testing.T, required map[string]struct{}) {
	t.Helper()
	err := filepath.WalkDir(filepath.Join("testdata", "fixtures"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if _, ok := required[rel]; !ok {
			t.Errorf("orphan fixture %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkDoc(t *testing.T, rows []Template) {
	t.Helper()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	got := renderDoc(rows)
	path := filepath.Join("..", "..", "..", "docs", "semgrep-templates.md")
	if compilertest.Updating() {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read docs/semgrep-templates.md: %v (go test ./internal/compiler/semgrep -update)", err)
	}
	if string(body) != got {
		t.Fatalf("docs/semgrep-templates.md drifted\n%s", got)
	}
}

func renderDoc(rows []Template) string {
	var b strings.Builder
	b.WriteString("# Semgrep templates\n\n")
	b.WriteString("A check with `engine: semgrep` and `ref: ipso:<id>` compiles one of these templates. Severity follows the check mode. Each template is one Semgrep rule.\n\n")
	b.WriteString("| id | title | languages |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", row.ID, row.Title, strings.Join(row.Languages, ", "))
	}
	return b.String()
}

var languageExt = map[string]string{
	"go":         "go",
	"java":       "java",
	"javascript": "js",
	"python":     "py",
	"typescript": "ts",
}

var wantTemplateIDs = []string{
	"go/http-client-timeout",
	"go/sql-no-string-query",
	"go/use-slog",
	"java/no-system-out",
	"java/sql-no-string-query",
	"javascript/no-eval",
	"javascript/no-inner-html",
	"python/no-pickle",
	"python/no-shell-true",
	"python/requests-timeout",
}
