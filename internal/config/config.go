package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const fileName = ".ipso/config.yaml"

// DefaultDecisions is the glob init writes and check uses when no config exists.
var DefaultDecisions = []string{"docs/decisions/**/*.md"}

// Config selects which files are EDR documents.
type Config struct {
	Decisions []string `yaml:"decisions"`
}

// Path returns the config path relative to a repository root.
func Path(root string) string {
	return filepath.Join(root, filepath.FromSlash(fileName))
}

// Default returns the config init writes.
func Default() Config {
	return Config{Decisions: append([]string{}, DefaultDecisions...)}
}

// Load reads the config. A missing file returns the default config and false.
func Load(root string) (Config, bool, error) {
	raw, err := os.ReadFile(Path(root))
	if errors.Is(err, os.ErrNotExist) {
		return Default(), false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Config{}, true, err
	}
	return cfg, true, nil
}

// Parse reads the bytes of a config file.
func Parse(raw []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("%s: %w", fileName, err)
	}
	if len(cfg.Decisions) == 0 {
		return Config{}, fmt.Errorf("%s: decisions must list at least one glob", fileName)
	}
	return cfg, nil
}

// Init writes the default config when it is absent.
// It returns true when it created the file.
func Init(root string) (bool, error) {
	path := Path(root)
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	raw, err := yaml.Marshal(Default())
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return false, err
	}
	return true, nil
}
