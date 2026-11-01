package edr

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Match lists files under root whose slash-separated path matches one pattern.
// A pattern may contain ** to cross directories. The result is sorted by path.
func Match(root string, patterns []string) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, pattern := range patterns {
			if MatchPath(pattern, rel) {
				matches = append(matches, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// MatchPath reports whether a slash-separated relative path matches one pattern.
func MatchPath(pattern, rel string) bool {
	return matchParts(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchParts(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		if matchParts(pattern[1:], path) {
			return true
		}
		if len(path) == 0 {
			return false
		}
		return matchParts(pattern, path[1:])
	}
	if len(path) == 0 {
		return false
	}
	ok, err := filepath.Match(pattern[0], path[0])
	if err != nil || !ok {
		return false
	}
	return matchParts(pattern[1:], path[1:])
}

// ReadFile parses an EDR file from disk.
func ReadFile(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	doc, err := Parse(string(raw))
	if err != nil {
		return Document{}, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}
