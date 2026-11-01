package bundle

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const manifestName = "manifest.json"

func writeTar(manifest []byte, files map[string][]byte) ([]byte, error) {
	if bytes.Contains(manifest, []byte{0}) {
		return nil, layoutErr("manifest")
	}
	names := make([]string, 0, len(files)+1)
	names = append(names, manifestName)
	for name := range files {
		if name == manifestName {
			return nil, layoutErr("tar path")
		}
		if _, err := cleanEntry(name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		body := manifest
		if name != manifestName {
			body = files[name]
		}
		if len(body) > entryLimit(name) {
			return nil, &compiler.Error{Code: compiler.CodeRefTooLarge, Err: fmt.Errorf("%s is %d bytes", name, len(body))}
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, layoutErr("tar path")
		}
		if _, err := tw.Write(body); err != nil {
			return nil, layoutErr("tar path")
		}
	}
	if err := tw.Close(); err != nil {
		return nil, layoutErr("tar path")
	}
	if buf.Len() > maxLayoutBytes {
		return nil, layoutErr("layout is too large")
	}
	return buf.Bytes(), nil
}

// entryLimit is the largest tar entry. An artifact is bound by MaxRefBytes. The manifest grows with the
// baseline digests it carries (ADR-0059), so only the layout limit binds it.
func entryLimit(name string) int {
	if name == manifestName {
		return maxLayoutBytes
	}
	return compiler.MaxRefBytes
}

func readTar(layer []byte) (manifest []byte, files map[string][]byte, err error) {
	if len(layer) > maxLayoutBytes {
		return nil, nil, layoutErr("layout is too large")
	}
	tr := tar.NewReader(bytes.NewReader(layer))
	files = map[string][]byte{}
	var sawManifest bool
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, layoutErr("tar")
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, nil, layoutErr("tar entry")
		}
		name, err := cleanEntry(hdr.Name)
		if err != nil {
			return nil, nil, err
		}
		if hdr.Size < 0 || hdr.Size > int64(entryLimit(name)) {
			return nil, nil, layoutErr("tar entry")
		}
		body, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return nil, nil, layoutErr("tar entry")
		}
		if int64(len(body)) != hdr.Size {
			return nil, nil, layoutErr("tar entry")
		}
		if name == manifestName {
			if sawManifest {
				return nil, nil, layoutErr("tar entry")
			}
			sawManifest = true
			manifest = body
			continue
		}
		if _, ok := files[name]; ok {
			return nil, nil, layoutErr("tar entry")
		}
		files[name] = body
	}
	if !sawManifest {
		return nil, nil, layoutErr("manifest")
	}
	return manifest, files, nil
}

func cleanEntry(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "\x00") {
		return "", layoutErr("tar path")
	}
	cleaned := path.Clean(name)
	if cleaned != name || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", layoutErr("tar path")
	}
	return cleaned, nil
}
