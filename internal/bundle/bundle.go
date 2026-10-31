// Package bundle packs a compiled build into a signed OCI image layout.
package bundle

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// Pack writes an OCI image layout for build. The returned digest is the
// sha256 of the image manifest. The same build bytes pack to the same digest.
func Pack(build compiler.Build, dir string) (string, error) {
	opened := map[string][]byte{}
	if _, err := compiler.Materialize(build.Manifest, func(rel string) ([]byte, error) {
		body, ok := lookup(build, rel)
		if !ok {
			return nil, fmt.Errorf("missing %s", rel)
		}
		opened[rel] = body
		return body, nil
	}); err != nil {
		return "", err
	}
	layer, err := writeTar(build.Manifest, opened)
	if err != nil {
		return "", err
	}
	return writeNewLayout(dir, layer)
}

// Sign adds one signature over the image manifest. A second signature is refused.
// The returned digest is the manifest pin and does not change when the signature is added.
func Sign(dir, keyPath string) (string, error) {
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	loaded, err := loadLayout(dir)
	if err != nil {
		return "", err
	}
	if loaded.sig != nil {
		return "", &compiler.Error{Code: CodeSignature, Err: fmt.Errorf("already signed")}
	}
	encoded, err := signBytes(key, loaded.manifest)
	if err != nil {
		return "", err
	}
	body, err := marshalDoc(signatureDoc{
		Version:   sigVersion,
		Digest:    loaded.digest,
		Signature: encoded,
	})
	if err != nil {
		return "", err
	}
	if err := addSignature(dir, loaded, body); err != nil {
		return "", err
	}
	return loaded.digest, nil
}

// Verify checks the pinned manifest digest and the signature, then checks every artifact hash.
// It does not open a network connection. Any failure is returned before a build is used.
func Verify(dir, digest, keyPath string) (compiler.Build, error) {
	if !ValidDigest(digest) {
		return compiler.Build{}, digestErr("manifest digest mismatch")
	}
	loaded, err := loadLayout(dir)
	if err != nil {
		return compiler.Build{}, err
	}
	if loaded.digest != digest {
		return compiler.Build{}, digestErr("manifest digest mismatch")
	}
	if loaded.sig == nil {
		return compiler.Build{}, &compiler.Error{Code: CodeUnsigned, Err: fmt.Errorf("bundle is unsigned")}
	}
	pub, err := loadPublicKey(keyPath)
	if err != nil {
		return compiler.Build{}, err
	}
	if err := verifyBytes(pub, loaded.manifest, loaded.sig.Signature); err != nil {
		return compiler.Build{}, err
	}
	manifest, files, err := readTar(loaded.layer)
	if err != nil {
		return compiler.Build{}, err
	}
	build, err := compiler.Materialize(manifest, func(rel string) ([]byte, error) {
		body, ok := files[rel]
		if !ok {
			return nil, fmt.Errorf("missing %s", rel)
		}
		return body, nil
	})
	if err != nil {
		return compiler.Build{}, err
	}
	expected := 0
	for _, entry := range build.Entries {
		expected += len(entry.Artifacts)
	}
	if len(files) != expected {
		return compiler.Build{}, layoutErr("tar entry")
	}
	return build, nil
}

func lookup(build compiler.Build, rel string) ([]byte, bool) {
	for key, artifacts := range build.Files {
		id, index, ok := splitEntryKey(key)
		if !ok {
			continue
		}
		for name, body := range artifacts {
			got, err := compiler.ArtifactRel(id, index, name)
			if err == nil && got == rel {
				return append([]byte(nil), body...), true
			}
		}
	}
	return nil, false
}

func splitEntryKey(key string) (string, int, bool) {
	id, rest, ok := strings.Cut(key, "/")
	if !ok || id == "" || strings.Contains(rest, "/") {
		return "", 0, false
	}
	index, err := strconv.Atoi(rest)
	if err != nil || strconv.Itoa(index) != rest || index < 0 {
		return "", 0, false
	}
	return id, index, true
}
