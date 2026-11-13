//go:build unix

package delivery

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDeliverKeepsTheModeOfTheDecisionFileUnderAUmask(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	path := filepath.Join(root, decisionFile)
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	if _, problems := deliver(t, root, item(checkA, ptr(edrA), noFloat)); len(problems) > 0 {
		t.Fatal(problems)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o664 {
		t.Fatalf("mode = %v, %v, want 0664", info.Mode().Perm(), err)
	}
}
