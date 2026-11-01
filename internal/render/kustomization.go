package render

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// kustomizationFiles are the names Kustomize looks for, in its own order.
var kustomizationFiles = []string{"kustomization.yaml", "kustomization.yml", "Kustomization"}

// kustomization holds the fields that can reach another directory, a git repository, or a URL.
// The Kustomize load restrictor covers the fields that name files, and it does not cover these.
type kustomization struct {
	Resources    []string `yaml:"resources"`
	Bases        []string `yaml:"bases"`
	Components   []string `yaml:"components"`
	Generators   []string `yaml:"generators"`
	Transformers []string `yaml:"transformers"`
	Validators   []string `yaml:"validators"`
}

// walkKustomization checks dir and everything it reaches. root and dir have symlinks resolved.
// An entry has to be a file or a directory inside the repository, so a remote base fails here with a
// clear reason rather than deep inside the tool. A directory is walked the same way, once.
func walkKustomization(root, dir string, visited map[string]struct{}) error {
	if _, seen := visited[dir]; seen {
		return nil
	}
	visited[dir] = struct{}{}
	if err := refuseSymlinks(dir); err != nil {
		return err
	}
	parsed, err := readKustomization(root, dir)
	if err != nil {
		return err
	}
	for _, list := range [][]string{parsed.Resources, parsed.Bases, parsed.Components, parsed.Generators, parsed.Transformers, parsed.Validators} {
		for _, entry := range list {
			// A generator, transformer, or validator can be inline YAML rather than a path. It names
			// nothing to walk, and the plugin flags it would need are never passed.
			if strings.Contains(entry, "\n") {
				continue
			}
			next, isDir, err := resolveEntry(root, dir, entry)
			if err != nil {
				return err
			}
			if !isDir {
				continue
			}
			if err := walkKustomization(root, next, visited); err != nil {
				return err
			}
		}
	}
	return nil
}

func readKustomization(root, dir string) (kustomization, error) {
	for _, name := range kustomizationFiles {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			return kustomization{}, pathErr("%s is not a regular file", shown(root, path))
		}
		if info.Size() > compiler.MaxRefBytes {
			return kustomization{}, pathErr("%s is larger than %d bytes", shown(root, path), compiler.MaxRefBytes)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return kustomization{}, runErr("%s", err)
		}
		var parsed kustomization
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return kustomization{}, pathErr("%s is not a kustomization file", shown(root, path))
		}
		return parsed, nil
	}
	return kustomization{}, pathErr("%s has no kustomization file", shown(root, dir))
}

// resolveEntry returns where one entry points and whether that is a directory.
func resolveEntry(root, dir, entry string) (string, bool, error) {
	if entry == "" || filepath.IsAbs(entry) || strings.Contains(entry, "://") {
		return "", false, remoteErr(entry)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(dir, filepath.FromSlash(entry)))
	if err != nil {
		return "", false, remoteErr(entry)
	}
	if !inside(root, resolved) {
		return "", false, &compiler.Error{Code: CodePath, Err: fmt.Errorf("%s leaves the repository", entry)}
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", false, remoteErr(entry)
	}
	return resolved, info.IsDir(), nil
}

func remoteErr(entry string) error {
	return &compiler.Error{Code: CodeRemote, Err: fmt.Errorf("%q is not a file or directory inside the repository, and ipso renders offline", entry)}
}

func inside(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func shown(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}
