package edr

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
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

// Loaded is one valid decision file. Shown is its slash-separated path from the root.
type Loaded struct {
	Shown string
	Doc   Document
	Rec   Record
}

// Load reads every file that matches a pattern. A file that does not read, validate, and decode is
// a problem, a line of the form "<path>: <problem>".
func Load(root string, patterns []string) ([]Loaded, []string, error) {
	files, err := Match(root, patterns)
	if err != nil {
		return nil, nil, err
	}
	var loaded []Loaded
	var problems []string
	for _, file := range files {
		shown := file
		if rel, err := filepath.Rel(root, file); err == nil {
			shown = filepath.ToSlash(rel)
		}
		doc, err := ReadFile(file)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %s", shown, err))
			continue
		}
		if found := Validate(doc); len(found) > 0 {
			for _, problem := range found {
				problems = append(problems, fmt.Sprintf("%s: %s", shown, problem))
			}
			continue
		}
		rec, err := RecordFrom(doc)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %s", shown, err))
			continue
		}
		loaded = append(loaded, Loaded{Shown: shown, Doc: doc, Rec: rec})
	}
	return loaded, problems, nil
}

// LoadInForce returns the records in force on the calendar date of now. Two records in force with
// one id are a problem too. A caller that acts on the decisions stops on any problem, so it never
// reflects part of them.
func LoadInForce(root string, patterns []string, now time.Time) ([]Loaded, []string, error) {
	all, problems, err := Load(root, patterns)
	if err != nil {
		return nil, nil, err
	}
	var loaded []Loaded
	seen := map[string]string{}
	for _, item := range all {
		if !item.Rec.InForce(now) {
			continue
		}
		if prev, ok := seen[item.Rec.ID]; ok {
			problems = append(problems, fmt.Sprintf("%s: duplicate-id: %s", item.Shown, prev))
			continue
		}
		seen[item.Rec.ID] = item.Shown
		loaded = append(loaded, item)
	}
	return loaded, problems, nil
}
