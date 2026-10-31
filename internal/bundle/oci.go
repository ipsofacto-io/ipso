package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// MaxLayoutBytes is the largest OCI layout pack and verify will accept.
	MaxLayoutBytes = 64 << 20

	mediaIndex     = "application/vnd.oci.image.index.v1+json"
	mediaManifest  = "application/vnd.oci.image.manifest.v1+json"
	mediaConfig    = "application/vnd.ipso.policy.config.v1+json"
	mediaLayer     = "application/vnd.ipso.policy.bundle.v1.tar"
	mediaSignature = "application/vnd.ipso.policy.signature.v1+json"

	roleBundle    = "bundle"
	roleSignature = "signature"
	layoutVersion = "1.0.0"
	configVersion = 1
	sigVersion    = 1

	maxLayoutBytes = MaxLayoutBytes
)

// CodeUnsigned means the layout has no signature.
const CodeUnsigned = "bundle-unsigned"

// CodeDigest means the pinned digest does not match the bundle, or a blob does not match its descriptor.
const CodeDigest = "bundle-digest"

// CodeSignature means the signature is missing its key, already present, or not valid for the manifest.
const CodeSignature = "bundle-signature"

// CodeLayout means the OCI layout, tar, or path is not acceptable.
const CodeLayout = "bundle-layout"

type ociLayoutFile struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type indexDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}

type descriptor struct {
	MediaType   string `json:"mediaType"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Annotations *anno  `json:"annotations,omitempty"`
}

type anno struct {
	Role    string `json:"io.ipso.policy.role"`
	Subject string `json:"io.ipso.policy.subject,omitempty"`
}

type imageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type policyConfig struct {
	Version int `json:"version"`
}

type signatureDoc struct {
	Version   int    `json:"version"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type layout struct {
	dir      string
	index    indexDoc
	digest   string
	manifest []byte
	layer    []byte
	sig      *signatureDoc
}

// ValidDigest reports whether s is a lowercase sha256 digest pin.
func ValidDigest(s string) bool {
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	return ok && isHex64(hexPart)
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func marshalDoc(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, layoutErr("json")
	}
	return buf.Bytes(), nil
}

func unmarshalDoc(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return layoutErr("json")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return layoutErr("json")
	}
	return nil
}

func rejectTotal(n int64) error {
	if n < 0 || n > maxLayoutBytes {
		return layoutErr("layout is too large")
	}
	return nil
}

func layoutErr(msg string) error {
	return &compiler.Error{Code: CodeLayout, Err: fmt.Errorf("%s", msg)}
}

func digestErr(msg string) error {
	return &compiler.Error{Code: CodeDigest, Err: fmt.Errorf("%s", msg)}
}

func writeNewLayout(dir string, layer []byte) (string, error) {
	if err := prepareDir(dir); err != nil {
		return "", err
	}
	configRaw, err := marshalDoc(policyConfig{Version: configVersion})
	if err != nil {
		return "", err
	}
	manifestRaw, err := marshalDoc(imageManifest{
		SchemaVersion: 2,
		MediaType:     mediaManifest,
		Config: descriptor{
			MediaType: mediaConfig,
			Digest:    digestOf(configRaw),
			Size:      int64(len(configRaw)),
		},
		Layers: []descriptor{{
			MediaType: mediaLayer,
			Digest:    digestOf(layer),
			Size:      int64(len(layer)),
		}},
	})
	if err != nil {
		return "", err
	}
	digest := digestOf(manifestRaw)
	indexRaw, err := marshalDoc(indexDoc{
		SchemaVersion: 2,
		MediaType:     mediaIndex,
		Manifests: []descriptor{{
			MediaType:   mediaManifest,
			Digest:      digest,
			Size:        int64(len(manifestRaw)),
			Annotations: &anno{Role: roleBundle},
		}},
	})
	if err != nil {
		return "", err
	}
	layoutRaw, err := marshalDoc(ociLayoutFile{ImageLayoutVersion: layoutVersion})
	if err != nil {
		return "", err
	}
	blobs := map[string][]byte{
		digestOf(configRaw): configRaw,
		digestOf(layer):     layer,
		digest:              manifestRaw,
	}
	total := int64(len(layoutRaw) + len(indexRaw))
	for _, body := range blobs {
		total += int64(len(body))
	}
	if err := rejectTotal(total); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := os.MkdirAll(diskPath(dir, path.Join("blobs", "sha256")), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	files := map[string][]byte{
		"oci-layout": layoutRaw,
		"index.json": indexRaw,
	}
	for digest, body := range blobs {
		hexPart := strings.TrimPrefix(digest, "sha256:")
		files[path.Join("blobs", "sha256", hexPart)] = body
	}
	for rel, body := range files {
		if err := writeFile(dir, rel, body, false); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return digest, nil
}

func prepareDir(dir string) error {
	if dir == "" || dir == "." {
		return layoutErr("layout path")
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		return os.Chmod(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return layoutErr("layout path")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return layoutErr("layout is not empty")
	}
	return os.Chmod(dir, 0o700)
}

func writeFile(dir, rel string, body []byte, overwrite bool) error {
	full := diskPath(dir, rel)
	back, err := filepath.Rel(dir, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return layoutErr("layout path")
	}
	parent := filepath.Dir(full)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return err
	}
	if !overwrite {
		if _, err := os.Lstat(full); err == nil {
			return layoutErr("layout path")
		}
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	info, err := os.Lstat(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = os.Remove(tmp)
		return layoutErr("layout path")
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func diskPath(dir, rel string) string {
	return filepath.Join(dir, filepath.FromSlash(rel))
}

func directorySize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return layoutErr("layout path")
		}
		total += info.Size()
		return rejectTotal(total)
	})
	if err != nil {
		var ce *compiler.Error
		if errors.As(err, &ce) {
			return 0, err
		}
		return 0, layoutErr("layout path")
	}
	return total, nil
}

func loadLayout(dir string) (layout, error) {
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return layout{}, layoutErr("layout path")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return layout{}, layoutErr("layout path")
	}
	defer func() { _ = root.Close() }()
	if err := walkLayout(root); err != nil {
		return layout{}, err
	}
	var file ociLayoutFile
	if err := readJSON(root, "oci-layout", &file); err != nil {
		return layout{}, err
	}
	if file.ImageLayoutVersion != layoutVersion {
		return layout{}, layoutErr("oci-layout")
	}
	var index indexDoc
	if err := readJSON(root, "index.json", &index); err != nil {
		return layout{}, err
	}
	if index.SchemaVersion != 2 || index.MediaType != mediaIndex {
		return layout{}, layoutErr("index")
	}
	bundleDesc, sigDesc, err := splitIndex(index)
	if err != nil {
		return layout{}, err
	}
	manifestRaw, err := readBlob(root, bundleDesc)
	if err != nil {
		return layout{}, err
	}
	if digestOf(manifestRaw) != bundleDesc.Digest {
		return layout{}, digestErr("manifest digest mismatch")
	}
	var manifest imageManifest
	if err := unmarshalDoc(manifestRaw, &manifest); err != nil {
		return layout{}, err
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != mediaManifest {
		return layout{}, layoutErr("manifest")
	}
	if manifest.Config.MediaType != mediaConfig || len(manifest.Layers) != 1 {
		return layout{}, layoutErr("manifest")
	}
	if manifest.Layers[0].MediaType != mediaLayer {
		return layout{}, layoutErr("manifest")
	}
	configRaw, err := readBlob(root, manifest.Config)
	if err != nil {
		return layout{}, err
	}
	var cfg policyConfig
	if err := unmarshalDoc(configRaw, &cfg); err != nil {
		return layout{}, err
	}
	if cfg.Version != configVersion {
		return layout{}, layoutErr("config")
	}
	layer, err := readBlob(root, manifest.Layers[0])
	if err != nil {
		return layout{}, err
	}
	referenced := map[string]struct{}{
		bundleDesc.Digest:         {},
		manifest.Config.Digest:    {},
		manifest.Layers[0].Digest: {},
	}
	out := layout{
		dir:      dir,
		index:    index,
		digest:   bundleDesc.Digest,
		manifest: manifestRaw,
		layer:    layer,
	}
	if sigDesc != nil {
		referenced[sigDesc.Digest] = struct{}{}
		if sigDesc.Annotations == nil || sigDesc.Annotations.Subject != bundleDesc.Digest {
			return layout{}, digestErr("signature digest mismatch")
		}
		sigRaw, err := readBlob(root, *sigDesc)
		if err != nil {
			return layout{}, err
		}
		var sig signatureDoc
		if err := unmarshalDoc(sigRaw, &sig); err != nil {
			return layout{}, err
		}
		if sig.Version != sigVersion || sig.Digest != bundleDesc.Digest || sig.Signature == "" {
			return layout{}, digestErr("signature digest mismatch")
		}
		out.sig = &sig
	}
	if err := blobsMatch(root, referenced); err != nil {
		return layout{}, err
	}
	return out, nil
}

func splitIndex(index indexDoc) (descriptor, *descriptor, error) {
	var bundleDesc descriptor
	var sigDesc *descriptor
	var sawBundle bool
	for _, item := range index.Manifests {
		if item.Annotations == nil || !ValidDigest(item.Digest) || item.Size < 0 {
			return descriptor{}, nil, layoutErr("index")
		}
		switch item.Annotations.Role {
		case roleBundle:
			if sawBundle || item.MediaType != mediaManifest || item.Annotations.Subject != "" {
				return descriptor{}, nil, layoutErr("index")
			}
			bundleDesc = item
			sawBundle = true
		case roleSignature:
			if sigDesc != nil || item.MediaType != mediaSignature || item.Annotations.Subject == "" {
				return descriptor{}, nil, layoutErr("index")
			}
			copied := item
			sigDesc = &copied
		default:
			return descriptor{}, nil, layoutErr("index")
		}
	}
	if !sawBundle {
		return descriptor{}, nil, layoutErr("index")
	}
	return bundleDesc, sigDesc, nil
}

func blobsMatch(root *os.Root, referenced map[string]struct{}) error {
	entries, err := fs.ReadDir(root.FS(), "blobs/sha256")
	if err != nil {
		return layoutErr("blobs")
	}
	if len(entries) != len(referenced) {
		return layoutErr("blobs")
	}
	for _, entry := range entries {
		digest := "sha256:" + entry.Name()
		if _, ok := referenced[digest]; !ok {
			return layoutErr("blobs")
		}
	}
	return nil
}

func walkLayout(root *os.Root) error {
	var total int64
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return layoutErr("layout path")
		}
		if name == "." {
			return nil
		}
		slash := path.Clean(name)
		switch {
		case slash == "oci-layout" || slash == "index.json":
			if d.IsDir() {
				return layoutErr("layout path")
			}
		case slash == "blobs" || slash == path.Join("blobs", "sha256"):
			if !d.IsDir() {
				return layoutErr("layout path")
			}
		case strings.HasPrefix(slash, "blobs/sha256/"):
			rest := strings.TrimPrefix(slash, "blobs/sha256/")
			if d.IsDir() || !isHex64(rest) {
				return layoutErr("layout path")
			}
		default:
			return layoutErr("layout path")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return layoutErr("layout path")
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return layoutErr("layout path")
		}
		total += info.Size()
		return rejectTotal(total)
	})
	if err != nil {
		var ce *compiler.Error
		if errors.As(err, &ce) {
			return err
		}
		return layoutErr("layout path")
	}
	return nil
}

func readJSON(root *os.Root, name string, dest any) error {
	raw, err := readRegular(root, name, maxLayoutBytes)
	if err != nil {
		return err
	}
	return unmarshalDoc(raw, dest)
}

func readBlob(root *os.Root, desc descriptor) ([]byte, error) {
	if !ValidDigest(desc.Digest) || desc.Size < 0 {
		return nil, digestErr("blob digest mismatch")
	}
	rel := path.Join("blobs", "sha256", strings.TrimPrefix(desc.Digest, "sha256:"))
	raw, err := readRegular(root, rel, desc.Size)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != desc.Size || digestOf(raw) != desc.Digest {
		return nil, digestErr("blob digest mismatch")
	}
	return raw, nil
}

func readRegular(root *os.Root, name string, limit int64) ([]byte, error) {
	if limit < 0 || limit > maxLayoutBytes {
		return nil, layoutErr("layout is too large")
	}
	info, err := fs.Lstat(root.FS(), name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, layoutErr("layout path")
	}
	if info.Size() > limit || info.Size() > maxLayoutBytes {
		return nil, layoutErr("layout is too large")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, layoutErr("layout path")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, layoutErr("layout path")
	}
	if int64(len(body)) > limit {
		return nil, layoutErr("layout is too large")
	}
	return body, nil
}

func addSignature(dir string, current layout, body []byte) error {
	digest := digestOf(body)
	if !ValidDigest(digest) {
		return digestErr("signature digest mismatch")
	}
	next := current.index
	next.Manifests = append(append([]descriptor{}, current.index.Manifests...), descriptor{
		MediaType: mediaSignature,
		Digest:    digest,
		Size:      int64(len(body)),
		Annotations: &anno{
			Role:    roleSignature,
			Subject: current.digest,
		},
	})
	raw, err := marshalDoc(next)
	if err != nil {
		return err
	}
	indexPath := diskPath(dir, "index.json")
	old, err := os.ReadFile(indexPath)
	if err != nil {
		return err
	}
	used, err := directorySize(dir)
	if err != nil {
		return err
	}
	if int64(len(old)) > used {
		return layoutErr("layout path")
	}
	// Replace index.json and add the signature blob. Nothing else grows.
	if err := rejectTotal(used - int64(len(old)) + int64(len(raw)) + int64(len(body))); err != nil {
		return err
	}
	rel := path.Join("blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
	if err := writeFile(dir, rel, body, false); err != nil {
		return err
	}
	if err := writeFile(dir, "index.json", raw, true); err != nil {
		_ = os.Remove(diskPath(dir, rel))
		return err
	}
	return nil
}
