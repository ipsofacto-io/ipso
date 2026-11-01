package edit

import (
	"errors"
	"fmt"
	"strings"
)

// FromCodexPatch reads the patch format of the Codex apply_patch tool. It applies each change in
// memory to what read returns for a path. A deleted file, and the old path of a moved file, become
// proposals with the tool "delete", so a caller can still guard those paths. Paths are returned as
// written. Context that does not match is an error, as in FromDiff.
func FromCodexPatch(read func(string) string, body string) ([]Proposal, error) {
	if !strings.Contains(body, "*** Begin Patch") {
		return nil, errors.New("the input is not an apply_patch body")
	}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	var proposals []Proposal
	var current *codexFile
	finish := func() error {
		if current == nil {
			return nil
		}
		done, err := current.finish()
		if err != nil {
			return err
		}
		proposals = append(proposals, done...)
		current = nil
		return nil
	}
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			if err := finish(); err != nil {
				return nil, err
			}
			current = &codexFile{path: strings.TrimPrefix(line, "*** Add File: "), added: true}
		case strings.HasPrefix(line, "*** Update File: "):
			if err := finish(); err != nil {
				return nil, err
			}
			name := strings.TrimPrefix(line, "*** Update File: ")
			current = &codexFile{path: name, source: strings.Split(strings.TrimSuffix(read(name), "\n"), "\n")}
		case strings.HasPrefix(line, "*** Delete File: "):
			if err := finish(); err != nil {
				return nil, err
			}
			proposals = append(proposals, Proposal{Tool: "delete", Path: strings.TrimPrefix(line, "*** Delete File: ")})
		case strings.HasPrefix(line, "*** Move to: ") && current != nil:
			current.moved = strings.TrimPrefix(line, "*** Move to: ")
		case strings.HasPrefix(line, "***"):
			if err := finish(); err != nil {
				return nil, err
			}
		case current != nil:
			if err := current.add(line); err != nil {
				return nil, err
			}
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return proposals, nil
}

// codexFile is one file section. A chunk runs from one @@ line to the next.
type codexFile struct {
	path   string
	moved  string
	added  bool
	source []string
	cursor int
	out    []string
	old    []string
	new    []string
	plus   []string
}

func (f *codexFile) add(line string) error {
	if strings.HasPrefix(line, "@@") {
		return f.flush()
	}
	if line == "" {
		return nil
	}
	text := line[1:]
	switch line[0] {
	case '+':
		f.new = append(f.new, text)
		f.plus = append(f.plus, text)
	case '-':
		f.old = append(f.old, text)
	case ' ':
		f.old = append(f.old, text)
		f.new = append(f.new, text)
	default:
		return fmt.Errorf("%s: a line starts with %q", f.path, string(line[0]))
	}
	return nil
}

// flush finds the chunk's old lines at or after the cursor and replaces them.
func (f *codexFile) flush() error {
	if len(f.old) == 0 && len(f.new) == 0 {
		return nil
	}
	at := len(f.source)
	if len(f.old) > 0 {
		at = -1
		for i := f.cursor; i+len(f.old) <= len(f.source); i++ {
			if equalLines(f.source[i:i+len(f.old)], f.old) {
				at = i
				break
			}
		}
		if at < 0 {
			return fmt.Errorf("%s: the patch does not match the file", f.path)
		}
	}
	f.out = append(f.out, f.source[f.cursor:at]...)
	f.out = append(f.out, f.new...)
	f.cursor = at + len(f.old)
	f.old, f.new = nil, nil
	return nil
}

func equalLines(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (f *codexFile) finish() ([]Proposal, error) {
	if err := f.flush(); err != nil {
		return nil, err
	}
	f.out = append(f.out, f.source[f.cursor:]...)
	proposal := Proposal{Tool: "patch", Path: f.path, Content: strings.Join(f.out, "\n") + "\n", Added: strings.Join(f.plus, "\n")}
	if f.moved == "" {
		return []Proposal{proposal}, nil
	}
	proposal.Path = f.moved
	return []Proposal{{Tool: "delete", Path: f.path}, proposal}, nil
}
