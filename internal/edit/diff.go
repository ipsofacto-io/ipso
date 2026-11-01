package edit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// MaxDiffBytes bounds a patch given to FromDiff.
const MaxDiffBytes = 16 << 20

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// FromDiff turns a unified diff into one proposal per file that exists afterwards. It applies each
// patch in memory to the file in repo, and context that does not match is an error, because a
// verdict on content that will never exist would mean nothing. It writes nothing.
func FromDiff(repo *os.Root, diff string) ([]Proposal, error) {
	if len(diff) > MaxDiffBytes {
		return nil, fmt.Errorf("the diff is larger than %d bytes", MaxDiffBytes)
	}
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	var proposals []Proposal
	for i := 0; i < len(lines); {
		line := lines[i]
		if strings.HasPrefix(line, "Binary files ") || line == "GIT binary patch" {
			return nil, errors.New("a binary patch cannot be evaluated")
		}
		if !strings.HasPrefix(line, "--- ") || i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
			i++
			continue
		}
		oldPath, err := diffPath(line[4:], "a/")
		if err != nil {
			return nil, err
		}
		newPath, err := diffPath(lines[i+1][4:], "b/")
		if err != nil {
			return nil, err
		}
		next, proposal, err := applyFile(repo, oldPath, newPath, lines, i+2)
		if err != nil {
			return nil, err
		}
		if newPath != "" {
			proposals = append(proposals, proposal)
		}
		i = next
	}
	if len(proposals) == 0 && !strings.Contains(diff, "--- ") {
		return nil, errors.New("the input is not a unified diff")
	}
	return proposals, nil
}

// diffPath returns the path after the prefix, or "" for /dev/null. A path outside the repository
// is an error.
func diffPath(field, prefix string) (string, error) {
	name, _, _ := strings.Cut(field, "\t")
	if name == "/dev/null" {
		return "", nil
	}
	name = strings.TrimPrefix(name, prefix)
	if !fs.ValidPath(name) || name == "." {
		return "", fmt.Errorf("the diff names the path %q", name)
	}
	return name, nil
}

func applyFile(repo *os.Root, oldPath, newPath string, lines []string, start int) (int, Proposal, error) {
	var source []string
	sourceEndsLine := true
	if oldPath != "" {
		data, err := repo.ReadFile(oldPath)
		if err != nil {
			return 0, Proposal{}, fmt.Errorf("%s: %w", oldPath, err)
		}
		text := string(data)
		sourceEndsLine = strings.HasSuffix(text, "\n")
		source = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if text == "" {
			source = nil
		}
	}
	var out, added []string
	cursor := 0
	endsLine := sourceEndsLine
	i := start
	for i < len(lines) {
		match := hunkHeader.FindStringSubmatch(lines[i])
		if match == nil {
			break
		}
		oldStart, _ := strconv.Atoi(match[1])
		oldCount, newCount := hunkCount(match[2]), hunkCount(match[4])
		if oldCount == 0 {
			oldStart++
		}
		if oldStart-1 < cursor || oldStart-1 > len(source) {
			return 0, Proposal{}, fmt.Errorf("%s: a hunk does not fit the file", oldPath)
		}
		out = append(out, source[cursor:oldStart-1]...)
		cursor = oldStart - 1
		i++
		for oldCount > 0 || newCount > 0 {
			if i >= len(lines) || lines[i] == "" {
				return 0, Proposal{}, fmt.Errorf("%s: a hunk is cut short", newOrOld(newPath, oldPath))
			}
			kind, text := lines[i][0], lines[i][1:]
			switch kind {
			case ' ', '-':
				if oldCount == 0 || cursor >= len(source) || source[cursor] != text {
					return 0, Proposal{}, fmt.Errorf("%s: the diff does not match the file", oldPath)
				}
				cursor++
				oldCount--
				if kind == ' ' {
					if newCount == 0 {
						return 0, Proposal{}, fmt.Errorf("%s: a hunk count is wrong", oldPath)
					}
					out = append(out, text)
					newCount--
				}
			case '+':
				if newCount == 0 {
					return 0, Proposal{}, fmt.Errorf("%s: a hunk count is wrong", newOrOld(newPath, oldPath))
				}
				out = append(out, text)
				added = append(added, text)
				newCount--
			case '\\':
				endsLine = lines[i-1][0] == '-'
			default:
				return 0, Proposal{}, fmt.Errorf("%s: a hunk has a line that starts with %q", newOrOld(newPath, oldPath), string(kind))
			}
			i++
		}
		if i < len(lines) && strings.HasPrefix(lines[i], `\ `) {
			endsLine = lines[i-1][0] == '-'
			i++
		}
	}
	out = append(out, source[cursor:]...)
	content := strings.Join(out, "\n")
	if len(out) > 0 && endsLine {
		content += "\n"
	}
	return i, Proposal{Tool: "patch", Path: newPath, Content: content, Added: strings.Join(added, "\n")}, nil
}

func hunkCount(field string) int {
	if field == "" {
		return 1
	}
	count, _ := strconv.Atoi(field)
	return count
}

func newOrOld(newPath, oldPath string) string {
	if newPath != "" {
		return newPath
	}
	return oldPath
}
