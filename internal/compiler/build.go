package compiler

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	buildDir  = ".ipso/build"
	stageName = "build.stage"
	prevName  = "build.prev"
	gitIgnore = "*\n"
)

// WriteBuild replaces .ipso/build with the compiled artifacts and a manifest.
// On error the previous build is left in place. A symlink at .ipso/build is refused.
// ids lists every in-force record, including records that compiled nothing.
func WriteBuild(root string, ids []DecisionRef, compiled []Compiled) error {
	if err := rejectDuplicateIDs(ids); err != nil {
		return err
	}
	dest := filepath.Join(root, filepath.FromSlash(buildDir))
	if err := refuseSymlink(dest); err != nil {
		return err
	}
	ipsoDir := filepath.Dir(dest)
	if err := os.MkdirAll(ipsoDir, 0o755); err != nil {
		return err
	}
	stage := filepath.Join(ipsoDir, stageName)
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	wrote := false
	defer func() {
		if !wrote {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := writeTree(stage, compiled); err != nil {
		return err
	}
	if err := swapBuild(dest, stage); err != nil {
		return err
	}
	wrote = true
	return nil
}

func rejectDuplicateIDs(ids []DecisionRef) error {
	seen := make(map[string]string, len(ids))
	for _, item := range ids {
		if !validSegment(item.ID) {
			return fmt.Errorf("decision id %q", item.ID)
		}
		if prev, ok := seen[item.ID]; ok {
			return &Error{Code: CodeDuplicateID, Err: fmt.Errorf("%s and %s share decision id %s", prev, item.Path, item.ID)}
		}
		seen[item.ID] = item.Path
	}
	return nil
}

func refuseSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(".ipso/build is a symlink")
	}
	return nil
}

func writeTree(stage string, compiled []Compiled) error {
	if err := os.WriteFile(filepath.Join(stage, ".gitignore"), []byte(gitIgnore), 0o644); err != nil {
		return err
	}
	entries := make([]Entry, 0, len(compiled))
	seen := make(map[string]struct{}, len(compiled))
	for _, item := range compiled {
		key := item.Entry.DecisionID + "/" + strconv.Itoa(item.Entry.CheckIndex)
		if _, ok := seen[key]; ok {
			return &Error{Code: CodeDuplicateID, Err: fmt.Errorf("decision %s check %d compiled twice", item.Entry.DecisionID, item.Entry.CheckIndex)}
		}
		seen[key] = struct{}{}
		entries = append(entries, item.Entry)
	}
	raw, err := MarshalManifest(entries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), raw, 0o644); err != nil {
		return err
	}
	for _, item := range compiled {
		for _, artifact := range item.Artifacts {
			path, err := artifactPath(stage, item.Entry.DecisionID, item.Entry.CheckIndex, artifact.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, artifact.Data, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// ArtifactRel is the slash-separated path of one artifact in a build.
func ArtifactRel(id string, index int, name string) (string, error) {
	full, err := artifactPath("stage", id, index, name)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel("stage", full)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

func artifactPath(stage, id string, index int, name string) (string, error) {
	if !validSegment(id) || !fs.ValidPath(name) {
		return "", &Error{Code: CodeArtifactName, Err: fmt.Errorf("artifact %q", name)}
	}
	rel := filepath.Join(id, strconv.Itoa(index), filepath.FromSlash(name))
	full := filepath.Join(stage, rel)
	back, err := filepath.Rel(stage, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", &Error{Code: CodeArtifactName, Err: fmt.Errorf("artifact %q", name)}
	}
	return full, nil
}

func validSegment(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, `/\`)
}

func swapBuild(dest, stage string) error {
	backup := filepath.Join(filepath.Dir(dest), prevName)
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	_, err := os.Lstat(dest)
	if err == nil {
		if err := os.Rename(dest, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, dest); err != nil {
		if _, statErr := os.Lstat(backup); statErr == nil {
			if restoreErr := os.Rename(backup, dest); restoreErr != nil {
				return errors.Join(err, restoreErr)
			}
		}
		return err
	}
	// The new build is in place. A leftover backup is removed on the next run.
	_ = os.RemoveAll(backup)
	// The manifest names waiver approvers. The directory stays private to the user.
	if err := os.Chmod(dest, 0o700); err != nil {
		return err
	}
	return nil
}
