//go:build cosign

package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCosignBlobSignature(t *testing.T) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Fatal(err)
	}
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
	if loaded.digest != digest || loaded.sig == nil {
		t.Fatalf("layout %s", loaded.digest)
	}
	work := t.TempDir()
	manifest := filepath.Join(work, "manifest.bin")
	bundlePath := filepath.Join(work, "bundle.json")
	if err := os.WriteFile(manifest, loaded.manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	wrapped, err := cosignBundle(loaded.manifest, loaded.sig.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	runCosign(t, work, cosign, "verify-blob", "--key", pub, "--bundle", bundlePath, "--insecure-ignore-tlog", manifest)

	keyDir := filepath.Join(work, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runCosign(t, keyDir, cosign, "generate-key-pair")
	payload := filepath.Join(keyDir, "payload")
	if err := os.WriteFile(payload, loaded.manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(keyDir, "signing-config.json")
	configBody := []byte("{\n  \"mediaType\": \"application/vnd.dev.sigstore.signingconfig.v0.2+json\",\n  \"rekorTlogUrls\": [],\n  \"tsaUrls\": []\n}\n")
	if err := os.WriteFile(config, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(keyDir, "signed.json")
	runCosign(t, keyDir, cosign, "sign-blob", "--yes", "--key", filepath.Join(keyDir, "cosign.key"), "--bundle", signed, "--signing-config", config, payload)
	raw, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		MessageSignature struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	key, err := loadPublicKey(filepath.Join(keyDir, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBytes(key, loaded.manifest, strings.TrimSpace(parsed.MessageSignature.Signature)); err != nil {
		t.Fatal(err)
	}
}

func cosignBundle(payload []byte, signature string) ([]byte, error) {
	sum := sha256.Sum256(payload)
	body := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{"hint": ""},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(sum[:]),
			},
			"signature": signature,
		},
	}
	return json.Marshal(body)
}

func runCosign(t *testing.T, dir, bin string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpass")
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s\n%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
}
