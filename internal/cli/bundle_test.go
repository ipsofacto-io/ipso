package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

func TestCheckPlanFromBundle(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	passing := strings.Replace(planBody, `"encrypted":false`, `"encrypted":true`, 1)
	writeRepoFile(t, root, "plan.json", passing)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	layout := filepath.Join(root, "layout")
	priv, pub := cliKeys(t)
	stdout, stderr, code := runAt(t, []string{"bundle", "pack", "--layout", layout})
	if code != 0 {
		t.Fatalf("pack %d\n%s\n%s", code, stdout, stderr)
	}
	digest := strings.TrimSpace(stdout)
	stdout, stderr, code = runAt(t, []string{"bundle", "sign", "--layout", layout, "--key", priv})
	if code != 0 || strings.TrimSpace(stdout) != digest {
		t.Fatalf("sign %d\n%s\n%s", code, stdout, stderr)
	}
	if err := os.RemoveAll(filepath.Join(root, ".ipso", "build")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = planAt(t, now, []string{"plan.json", "--bundle", layout, "--digest", digest, "--key", pub})
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "ebs-encrypted: checks[0] (block): pass") {
		t.Fatalf("stdout %s", stdout)
	}
}

func TestCheckPlanRefusesUnsignedBundle(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	writeRepoFile(t, root, "plan.json", planBody)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	layout := filepath.Join(root, "layout")
	_, pub := cliKeys(t)
	stdout, stderr, code := runAt(t, []string{"bundle", "pack", "--layout", layout})
	if code != 0 {
		t.Fatalf("pack %d\n%s\n%s", code, stdout, stderr)
	}
	digest := strings.TrimSpace(stdout)
	stdout, stderr, code = planAt(t, now, []string{"plan.json", "--bundle", layout, "--digest", digest, "--key", pub})
	if code != 1 || !strings.Contains(stderr, "bundle-unsigned") || strings.Contains(stdout, "pass") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckPlanRefusesDigestMismatch(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	writeRepoFile(t, root, "plan.json", planBody)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	layout := filepath.Join(root, "layout")
	priv, pub := cliKeys(t)
	stdout, stderr, code := runAt(t, []string{"bundle", "pack", "--layout", layout})
	if code != 0 {
		t.Fatalf("pack %d\n%s\n%s", code, stdout, stderr)
	}
	digest := strings.TrimSpace(stdout)
	if _, stderr, code = runAt(t, []string{"bundle", "sign", "--layout", layout, "--key", priv}); code != 0 {
		t.Fatalf("sign %d %s", code, stderr)
	}
	bad := digest[:len(digest)-1] + "0"
	if strings.HasSuffix(digest, "0") {
		bad = digest[:len(digest)-1] + "1"
	}
	stdout, stderr, code = planAt(t, now, []string{"plan.json", "--bundle", layout, "--digest", bad, "--key", pub})
	if code != 1 || !strings.Contains(stderr, "bundle-digest") || strings.Contains(stdout, "pass") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBundleUsage(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	if _, _, code := runAt(t, []string{"bundle"}); code != 2 {
		t.Fatalf("code %d", code)
	}
	if _, _, code := runAt(t, []string{"check", "plan", "plan.json", "--bundle", "layout"}); code != 2 {
		t.Fatalf("code %d", code)
	}
	if _, _, code := runAt(t, []string{"bundle", "verify", "--layout", "layout", "--digest", "sha256:zz", "--key", "key.pub"}); code != 2 {
		t.Fatalf("code %d", code)
	}
}

func runAt(t *testing.T, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(args, &stdout, &stderr, deps{now: time.Now, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func cliKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	priv := filepath.Join(dir, "key.pem")
	pub := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}
