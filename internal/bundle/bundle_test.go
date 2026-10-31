package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

func TestPackIsDeterministic(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	a := t.TempDir()
	b := t.TempDir()
	first, err := Pack(build, filepath.Join(a, "layout"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Pack(build, filepath.Join(b, "layout"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !ValidDigest(first) {
		t.Fatalf("digests %s %s", first, second)
	}
	info, err := os.Stat(filepath.Join(a, "layout"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestVerifySignedBundle(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	dir := filepath.Join(t.TempDir(), "layout")
	priv, pub := writeKeys(t)
	digest, err := Pack(build, dir)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	if signed != digest {
		t.Fatalf("sign digest %s want %s", signed, digest)
	}
	if _, err := Sign(dir, priv); !codeIs(err, CodeSignature) {
		t.Fatalf("second sign %v", err)
	}
	got, err := Verify(dir, digest, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Manifest, build.Manifest) {
		t.Fatalf("manifest bytes changed")
	}
	if string(got.Files[build.Entries[0].DecisionID+"/0"]["policy.rego"]) != "package ipso\n" {
		t.Fatalf("artifact %q", got.Files)
	}
}

func TestRefusesUnsignedAndMismatch(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	dir := filepath.Join(t.TempDir(), "layout")
	priv, pub := writeKeys(t)
	digest, err := Pack(build, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, digest, pub); !codeIs(err, CodeUnsigned) {
		t.Fatalf("unsigned %v", err)
	}
	flipped := digest[:len(digest)-1] + flipHex(digest[len(digest)-1])
	if _, err := Verify(dir, flipped, pub); !codeIs(err, CodeDigest) {
		t.Fatalf("digest %v", err)
	}
	if _, err := Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
	_, otherPub := writeKeys(t)
	if _, err := Verify(dir, digest, otherPub); !codeIs(err, CodeSignature) {
		t.Fatalf("wrong key %v", err)
	}
	if _, err := Verify(dir, flipped, pub); !codeIs(err, CodeDigest) {
		t.Fatalf("signed digest %v", err)
	}
}

func TestRefusesTamperedLayer(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	dir := filepath.Join(t.TempDir(), "layout")
	priv, pub := writeKeys(t)
	digest, err := Pack(build, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := flipBlob(dir, loaded.layer); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, digest, pub); !codeIs(err, CodeDigest) {
		t.Fatalf("layer %v", err)
	}
}

func TestRefusesSymlinkAndExtraFile(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	root := t.TempDir()
	dir := filepath.Join(root, "layout")
	_, pub := writeKeys(t)
	digest, err := Pack(build, dir)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := writeKeys(t)
	if _, err := Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(note, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, digest, pub); !codeIs(err, CodeLayout) {
		t.Fatalf("extra %v", err)
	}
	if err := os.Remove(note); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.json")
	raw, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "index.json")
	if err := os.WriteFile(other, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(index); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, index); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, digest, pub); !codeIs(err, CodeLayout) {
		t.Fatalf("symlink %v", err)
	}
}

func TestRefusesTarEscapeAndInnerDigest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "layout")
	priv, pub := writeKeys(t)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("x")
	hdr := &tar.Header{
		Name:     "../outside",
		Mode:     0o644,
		Size:     int64(len(body)),
		ModTime:  time.Unix(0, 0).UTC(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	digest, err := writeNewLayout(dir, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, digest, pub); !codeIs(err, CodeLayout) {
		t.Fatalf("escape %v", err)
	}

	inner := filepath.Join(t.TempDir(), "inner")
	good := []byte("package good\n")
	bad := []byte("package bad\n")
	sum := sha256.Sum256(good)
	build := sampleBuild(t, bad, hex.EncodeToString(sum[:]))
	rel, err := compiler.ArtifactRel(build.Entries[0].DecisionID, 0, "policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	layer, err := writeTar(build.Manifest, map[string][]byte{rel: bad})
	if err != nil {
		t.Fatal(err)
	}
	digest, err = writeNewLayout(inner, layer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(inner, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(inner, digest, pub); !codeIs(err, compiler.CodeBuildDigest) {
		t.Fatalf("inner %v", err)
	}
}

func TestRefusesOccupiedLayout(t *testing.T) {
	build := sampleBuild(t, []byte("package ipso\n"), "")
	dir := filepath.Join(t.TempDir(), "layout")
	if _, err := Pack(build, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(build, dir); !codeIs(err, CodeLayout) {
		t.Fatalf("second pack %v", err)
	}
	if err := rejectTotal(MaxLayoutBytes + 1); err == nil {
		t.Fatal("accepted a large layout")
	}
}

func sampleBuild(t *testing.T, body []byte, digest string) compiler.Build {
	t.Helper()
	if digest == "" {
		sum := sha256.Sum256(body)
		digest = hex.EncodeToString(sum[:])
	}
	entry := compiler.Entry{
		DecisionID:      "01M5C5QEHHNXJ3D7X2ZCMGXQT7",
		Slug:            "sample",
		CheckIndex:      0,
		Engine:          "opa",
		Mode:            "block",
		Target:          "terraform-plan",
		ValidFrom:       "2026-01-01",
		Compiler:        "opa",
		CompilerVersion: "test",
		Artifacts:       []compiler.ManifestArtifact{{Name: "policy.rego", SHA256: digest}},
	}
	raw, err := compiler.MarshalManifest([]compiler.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	return compiler.Build{
		Manifest: raw,
		Entries:  []compiler.Entry{entry},
		Files: map[string]map[string][]byte{
			entry.DecisionID + "/0": {"policy.rego": body},
		},
	}
}

func writeKeys(t *testing.T) (string, string) {
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

func flipBlob(dir string, body []byte) error {
	matches, err := filepath.Glob(filepath.Join(dir, "blobs", "sha256", "*"))
	if err != nil {
		return err
	}
	for _, name := range matches {
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Equal(raw, body) {
			raw[0] ^= 0xff
			return os.WriteFile(name, raw, 0o600)
		}
	}
	return errors.New("blob not found")
}

func flipHex(b byte) string {
	if b == '0' {
		return "1"
	}
	return "0"
}

func codeIs(err error, code string) bool {
	var ce *compiler.Error
	return errors.As(err, &ce) && ce.Code == code
}
