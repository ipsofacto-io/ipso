package edit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func diffRepo(t *testing.T, files map[string]string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func TestFromDiffAppliesEveryKindOfChange(t *testing.T) {
	repo := diffRepo(t, map[string]string{"a.go": "one\ntwo\nthree\n", "gone.go": "x\n"})
	diff := `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
--- /dev/null
+++ b/new/b.go
@@ -0,0 +1,2 @@
+hello
+world
--- a/gone.go
+++ /dev/null
@@ -1 +0,0 @@
-x
`
	got, err := FromDiff(repo, diff)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Path != "a.go" || got[0].Content != "one\nTWO\nthree\n" || got[0].Added != "TWO" {
		t.Errorf("edit: %+v", got[0])
	}
	if got[1].Path != "new/b.go" || got[1].Content != "hello\nworld\n" {
		t.Errorf("new file: %+v", got[1])
	}
}

func TestFromDiffKeepsAMissingFinalNewline(t *testing.T) {
	repo := diffRepo(t, map[string]string{"a": "one\n"})
	got, err := FromDiff(repo, "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-one\n+two\n\\ No newline at end of file\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Content != "two" {
		t.Fatalf("content %q", got[0].Content)
	}
}

func TestFromDiffTracksTheFinalNewline(t *testing.T) {
	repo := diffRepo(t, map[string]string{"bare": "one\ntwo", "ended": "one\n"})
	got, err := FromDiff(repo, "--- a/bare\n+++ b/bare\n@@ -1,2 +1,3 @@\n one\n+mid\n two\n\\ No newline at end of file\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Content != "one\nmid\ntwo" {
		t.Errorf("an insert keeps a missing newline: %q", got[0].Content)
	}
	got, err = FromDiff(repo, "--- a/bare\n+++ b/bare\n@@ -2 +2 @@\n-two\n\\ No newline at end of file\n+TWO\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Content != "one\nTWO\n" {
		t.Errorf("a patch can add the newline: %q", got[0].Content)
	}
}

func TestFromDiffRefuses(t *testing.T) {
	repo := diffRepo(t, map[string]string{"a": "one\n"})
	for name, tc := range map[string]struct{ diff, want string }{
		"context":   {"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-other\n+two\n", "does not match"},
		"traversal": {"--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-one\n+two\n", "names the path"},
		"absolute":  {"--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-one\n+two\n", "names the path"},
		"binary":    {"Binary files a/a and b/a differ\n", "binary"},
		"short":     {"--- a/a\n+++ b/a\n@@ -1 +1,2 @@\n-one\n", "cut short"},
		"position":  {"--- a/a\n+++ b/a\n@@ -9 +9 @@\n-one\n+two\n", "does not fit"},
		"not diff":  {"just text\n", "not a unified diff"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FromDiff(repo, tc.diff); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestFromDiffRefusesASymlinkOutOfTheRepository(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	repo, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	if _, err := FromDiff(repo, "--- a/link\n+++ b/link\n@@ -1 +1 @@\n-one\n+two\n"); err == nil {
		t.Fatal("a link out of the repository was read")
	}
}

func TestFromCodexPatch(t *testing.T) {
	read := func(name string) string {
		if name == "a.go" {
			return "one\ntwo\nthree\nfour\n"
		}
		return ""
	}
	got, err := FromCodexPatch(read, `*** Begin Patch
*** Update File: a.go
@@
 one
-two
+TWO
@@ three
-four
+FOUR
*** Add File: new/b.go
+hello
+world
*** Update File: a.go
*** Move to: moved.go
@@
 one
*** Delete File: gone.go
*** End Patch`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Path != "a.go" || got[0].Content != "one\nTWO\nthree\nFOUR\n" || got[0].Added != "TWO\nFOUR" {
		t.Errorf("update: %+v", got[0])
	}
	if got[1].Path != "new/b.go" || got[1].Content != "hello\nworld\n" {
		t.Errorf("add: %+v", got[1])
	}
	if got[2].Tool != "delete" || got[2].Path != "a.go" || got[3].Path != "moved.go" {
		t.Errorf("move: %+v %+v", got[2], got[3])
	}
	if got[4].Tool != "delete" || got[4].Path != "gone.go" {
		t.Errorf("delete: %+v", got[4])
	}
}

func TestFromCodexPatchRefuses(t *testing.T) {
	read := func(string) string { return "one\n" }
	for name, tc := range map[string]struct{ body, want string }{
		"not a patch": {"rm -rf /", "not an apply_patch"},
		"context":     {"*** Begin Patch\n*** Update File: a\n@@\n-other\n+x\n*** End Patch", "does not match"},
		"bad line":    {"*** Begin Patch\n*** Update File: a\n@@\nnope\n*** End Patch", "starts with"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FromCodexPatch(read, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
}
