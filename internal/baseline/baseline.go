// Package baseline reads and writes the local baseline file and computes violation fingerprints.
//
// A fingerprint is HMAC-SHA-256 under a per-repository salt, so a server that stores digests cannot
// confirm a guessed path or address. The contract is ADR-0059.
package baseline

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// RelPath is the file path relative to the repository root.
	RelPath = ".ipso/baseline.json"
	// CodeFile means the baseline file cannot be used.
	CodeFile = "baseline-file"

	fileVersion  = 1
	maxFileBytes = 64 << 20
	domain       = "ipso-fingerprint-v1"
)

// Scope names the input of one run. A check holds one set of fingerprints per scope, and the
// scope feeds the digest, so a baseline for one input never covers another.
type Scope struct {
	Env   string
	Input string
}

var inputName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidInput reports whether name can be used with --input.
func ValidInput(name string) bool {
	return inputName.MatchString(name)
}

// Check is the recorded fingerprints of one check for one scope.
type Check struct {
	DecisionID   string   `json:"decision_id"`
	CheckIndex   int      `json:"check_index"`
	Env          string   `json:"env,omitempty"`
	Input        string   `json:"input,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

// File is the local baseline file. The salt is not a secret from repository readers, and it is never uploaded.
type File struct {
	Version int     `json:"baseline_version"`
	Salt    string  `json:"salt"`
	Checks  []Check `json:"checks"`
}

// New returns an empty file with a fresh salt.
func New() (File, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return File{}, err
	}
	return File{Version: fileVersion, Salt: hex.EncodeToString(salt), Checks: []Check{}}, nil
}

// Read loads the file under root. found is false when it does not exist.
func Read(root string) (file File, found bool, err error) {
	path := filepath.Join(root, filepath.FromSlash(RelPath))
	for _, name := range []string{filepath.Dir(path), path} {
		info, statErr := os.Lstat(name)
		if errors.Is(statErr, fs.ErrNotExist) {
			return File{}, false, nil
		}
		if statErr != nil {
			return File{}, false, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return File{}, false, fileError(fmt.Errorf("%s is a symlink", name))
		}
	}
	opened, err := os.Open(path)
	if err != nil {
		return File{}, false, err
	}
	defer func() { _ = opened.Close() }()
	raw, err := io.ReadAll(io.LimitReader(opened, maxFileBytes+1))
	if err != nil {
		return File{}, false, err
	}
	file, err = Parse(raw)
	if err != nil {
		return File{}, false, err
	}
	return file, true, nil
}

// Parse decodes and checks file bytes.
func Parse(raw []byte) (File, error) {
	if len(raw) > maxFileBytes {
		return File{}, fileError(fmt.Errorf("larger than %d bytes", maxFileBytes))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file File
	if err := decoder.Decode(&file); err != nil {
		return File{}, fileError(err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return File{}, fileError(errors.New("data after the document"))
	}
	if err := file.validate(); err != nil {
		return File{}, fileError(err)
	}
	return file, nil
}

func (f File) validate() error {
	if f.Version != fileVersion {
		return fmt.Errorf("baseline_version %d", f.Version)
	}
	if !compiler.ValidDigest(f.Salt) {
		return errors.New("salt is not 64 lowercase hex characters")
	}
	seenChecks := map[string]struct{}{}
	seenDigests := map[string]map[string]struct{}{}
	for _, check := range f.Checks {
		if check.DecisionID == "" || check.CheckIndex < 0 {
			return errors.New("a check has no decision id or a negative index")
		}
		if check.Input != "" && !ValidInput(check.Input) {
			return errors.New("a check has an input name that is not valid")
		}
		key := check.DecisionID + "/" + strconv.Itoa(check.CheckIndex)
		scopeKey := key + "\x00" + check.Env + "\x00" + check.Input
		if _, ok := seenChecks[scopeKey]; ok {
			return fmt.Errorf("check %s is listed twice for one env and input", key)
		}
		seenChecks[scopeKey] = struct{}{}
		digests := seenDigests[check.DecisionID]
		if digests == nil {
			digests = map[string]struct{}{}
			seenDigests[check.DecisionID] = digests
		}
		for _, digest := range check.Fingerprints {
			if !compiler.ValidDigest(digest) {
				return fmt.Errorf("check %s has a fingerprint that is not 64 lowercase hex characters", key)
			}
			if _, ok := digests[digest]; ok {
				return fmt.Errorf("decision %s repeats a fingerprint", check.DecisionID)
			}
			digests[digest] = struct{}{}
		}
		if len(digests) > compiler.MaxBaselineFingerprints {
			return fmt.Errorf("decision %s has more than %d fingerprints", check.DecisionID, compiler.MaxBaselineFingerprints)
		}
	}
	return nil
}

// Marshal encodes the file deterministically, one fingerprint per line, so a merge stays readable.
func (f File) Marshal() ([]byte, error) {
	out := File{Version: fileVersion, Salt: f.Salt, Checks: make([]Check, 0, len(f.Checks))}
	for _, check := range f.Checks {
		digests := append([]string{}, check.Fingerprints...)
		sort.Strings(digests)
		out.Checks = append(out.Checks, Check{DecisionID: check.DecisionID, CheckIndex: check.CheckIndex, Env: check.Env, Input: check.Input, Fingerprints: digests})
	}
	sort.Slice(out.Checks, func(i, j int) bool {
		a, b := out.Checks[i], out.Checks[j]
		if a.DecisionID != b.DecisionID {
			return a.DecisionID < b.DecisionID
		}
		if a.CheckIndex != b.CheckIndex {
			return a.CheckIndex < b.CheckIndex
		}
		if a.Env != b.Env {
			return a.Env < b.Env
		}
		return a.Input < b.Input
	})
	if err := out.validate(); err != nil {
		return nil, fileError(err)
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Find returns the position of the recorded check for one scope, or -1.
func (f File) Find(decisionID string, index int, scope Scope) int {
	return slices.IndexFunc(f.Checks, func(check Check) bool {
		return check.DecisionID == decisionID && check.CheckIndex == index && check.Env == scope.Env && check.Input == scope.Input
	})
}

// Fingerprints returns one digest per violation, in order, and an empty string for a violation that
// cannot be baselined. Repeats of one identity in one check are numbered from 1 in the order given.
func Fingerprints(salt string, entry compiler.Entry, scope Scope, violations []compiler.Violation) ([]string, error) {
	key, err := hex.DecodeString(salt)
	if err != nil {
		return nil, fileError(errors.New("salt is not hex"))
	}
	digests := make([]string, len(violations))
	occurrences := map[string]int{}
	for i, violation := range violations {
		if violation.Identity == nil {
			continue
		}
		identity := encodeFields(violation.Identity)
		occurrences[string(identity)]++
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(domain))
		mac.Write(encodeFields([]string{entry.DecisionID, strconv.Itoa(entry.CheckIndex), entry.Engine, scope.Env, scope.Input}))
		mac.Write(identity)
		mac.Write(encodeFields([]string{strconv.Itoa(occurrences[string(identity)])}))
		digests[i] = hex.EncodeToString(mac.Sum(nil))
	}
	return digests, nil
}

// encodeFields writes each field as a big-endian uint32 byte length and its bytes, so fields cannot run together.
func encodeFields(fields []string) []byte {
	var buf bytes.Buffer
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		buf.Write(length[:])
		buf.WriteString(field)
	}
	return buf.Bytes()
}

// Apply marks the violations the entry's stamped baseline covers for this scope. An error is never
// baselined, and a check a waiver already covers keeps that waiver.
func Apply(entry compiler.Entry, scope Scope, outcome compiler.Outcome) (compiler.Outcome, error) {
	if entry.Baseline == nil || outcome.Err != nil || outcome.Waived || len(outcome.Violations) == 0 {
		return outcome, nil
	}
	digests, err := Fingerprints(entry.Baseline.Salt, entry, scope, outcome.Violations)
	if err != nil {
		return outcome, err
	}
	recorded := make(map[string]struct{}, len(entry.Baseline.Fingerprints))
	for _, digest := range entry.Baseline.Fingerprints {
		recorded[digest] = struct{}{}
	}
	marked := slices.Clone(outcome.Violations)
	for i, digest := range digests {
		_, covered := recorded[digest]
		marked[i].Baselined = digest != "" && covered
	}
	outcome.Violations = marked
	return outcome, nil
}

func fileError(err error) error {
	return &compiler.Error{Code: CodeFile, Err: err}
}
