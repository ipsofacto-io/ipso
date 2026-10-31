package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const maxKeyBytes = 16 << 10

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	der, err := decodePEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, sigErr("private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !isP256(key.Curve) {
		return nil, sigErr("private key")
	}
	return key, nil
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	der, err := decodePEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, sigErr("public key")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !isP256(key.Curve) {
		return nil, sigErr("public key")
	}
	return key, nil
}

func decodePEM(path, blockType string) ([]byte, error) {
	raw, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(trimSpace(rest)) != 0 || block.Type != blockType || len(block.Bytes) == 0 {
		return nil, sigErr("key pem")
	}
	return block.Bytes, nil
}

func readKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, sigErr("key file")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, sigErr("key file")
	}
	if info.Size() > maxKeyBytes {
		return nil, sigErr("key file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, sigErr("key file")
	}
	if len(raw) > maxKeyBytes {
		return nil, sigErr("key file")
	}
	return raw, nil
}

func signBytes(key *ecdsa.PrivateKey, payload []byte) (string, error) {
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return "", sigErr("sign")
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyBytes(key *ecdsa.PublicKey, payload []byte, encoded string) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return sigErr("signature mismatch")
	}
	sum := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(key, sum[:], raw) {
		return sigErr("signature mismatch")
	}
	return nil
}

func isP256(curve elliptic.Curve) bool {
	return curve != nil && curve.Params().Name == "P-256"
}

func sigErr(msg string) error {
	return &compiler.Error{Code: CodeSignature, Err: fmt.Errorf("%s", msg)}
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}
