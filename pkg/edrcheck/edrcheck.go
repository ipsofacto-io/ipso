// Package edrcheck validates EDR files from bytes, the way bare `ipso check` validates them
// from disk. It is the one public entry point for callers outside this module, such as the
// ipso-server GitHub App. Everything else in this module stays internal.
package edrcheck

import (
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
)

// DefaultGlobs returns the globs that apply when a repository has no .ipso/config.yaml.
func DefaultGlobs() []string {
	return config.Default().Decisions
}

// ParseGlobs reads the decision globs from the bytes of .ipso/config.yaml.
func ParseGlobs(raw []byte) ([]string, error) {
	cfg, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	return cfg.Decisions, nil
}

// IsDecision reports whether a slash-separated path relative to the repository root matches
// one of the globs.
func IsDecision(globs []string, path string) bool {
	for _, glob := range globs {
		if edr.MatchPath(glob, path) {
			return true
		}
	}
	return false
}

// Validate returns the problems of one EDR file. None means the file is valid.
func Validate(text string) []string {
	doc, err := edr.Parse(text)
	if err != nil {
		return []string{err.Error()}
	}
	return edr.Validate(doc)
}
