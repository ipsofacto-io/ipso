// Package delivery brings the accepted agent-edit checks of a control plane into a repository (ADR-0120).
// It reads an answer the person fetched themselves and opens no connection. For each check it writes the
// Rego under .ipso/checks, which the agent hooks protect, and adds one entry to the checks of the decision
// file that holds the EDR id the answer names. ipso compile then builds it like any repository Rego.
package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/rules"
	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

// Dir is where the Rego of a delivered check is written.
const Dir = ".ipso/checks"

const (
	// MaxAnswerBytes bounds the answer read from a file or a pipe.
	MaxAnswerBytes = 4 << 20
	// MaxItems bounds the checks of one answer. The server serves at most 100 in a page.
	MaxItems = 1000
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ulidPattern   = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Item is one accepted check as the control plane serves it. Rego and RegoSHA256 are null for a check that
// was accepted for a version of its decision that is not the one in force.
type Item struct {
	ID              string  `json:"id"`
	DecisionID      string  `json:"decision_id"`
	EDRID           *string `json:"edr_id"`
	DecisionVersion int     `json:"decision_version"`
	VersionInForce  int     `json:"version_in_force"`
	Rego            *string `json:"rego"`
	RegoSHA256      *string `json:"rego_sha256"`
}

// Answer is the body of GET /v1/accepted-checks.
type Answer struct {
	AcceptedChecks []Item `json:"accepted_checks"`
}

// held reports whether the check was accepted for a version that is not in force. It is never delivered.
func (i Item) held() bool { return i.DecisionVersion != i.VersionInForce }

// Decode reads an answer and checks its shape. Anything it returns can be used as a file name and compared
// with a digest, so a malformed answer stops here and nothing is written.
func Decode(r io.Reader) (Answer, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxAnswerBytes+1))
	if err != nil {
		return Answer{}, fmt.Errorf("read the answer: %w", err)
	}
	if len(raw) > MaxAnswerBytes {
		return Answer{}, fmt.Errorf("the answer is over %d bytes", MaxAnswerBytes)
	}
	var answer Answer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return Answer{}, fmt.Errorf("the answer is not JSON of accepted checks: %w", err)
	}
	if len(answer.AcceptedChecks) > MaxItems {
		return Answer{}, fmt.Errorf("the answer holds more than %d checks", MaxItems)
	}
	seen := map[string]bool{}
	for index, item := range answer.AcceptedChecks {
		if err := item.validate(); err != nil {
			return Answer{}, fmt.Errorf("accepted_checks[%d]: %w", index, err)
		}
		if seen[item.ID] {
			return Answer{}, fmt.Errorf("accepted_checks[%d]: the check %s is listed twice", index, item.ID)
		}
		seen[item.ID] = true
	}
	return answer, nil
}

func (i Item) validate() error {
	switch {
	case !uuidPattern.MatchString(i.ID):
		return errors.New("id is not a lowercase UUID")
	case !uuidPattern.MatchString(i.DecisionID):
		return errors.New("decision_id is not a lowercase UUID")
	case i.EDRID != nil && !ulidPattern.MatchString(*i.EDRID):
		return errors.New("edr_id is not a ULID")
	case i.DecisionVersion < 1 || i.VersionInForce < 1:
		return errors.New("a version is not a positive number")
	}
	if i.held() {
		return nil
	}
	switch {
	case i.Rego == nil || i.RegoSHA256 == nil:
		return errors.New("a check for the version in force carries its rego and its digest")
	case len(*i.Rego) > compiler.MaxRefBytes:
		return fmt.Errorf("rego is over %d bytes", compiler.MaxRefBytes)
	case !digestPattern.MatchString(*i.RegoSHA256):
		return errors.New("rego_sha256 is not 64 lowercase hex digits")
	}
	return nil
}

// Status is what happened to one check.
type Status string

const (
	// Added: the Rego or the entry was written.
	Added Status = "added"
	// Present: the Rego and the entry were already there, and nothing was written.
	Present Status = "present"
	// Held: accepted for a version of its decision that is not in force, so it was not delivered.
	Held Status = "held"
	// Skipped: no decision file in this checkout, in force, holds the EDR id of its decision.
	Skipped Status = "skipped"
)

// Result is the outcome for one check, in the order of the answer. File is the decision file of an added or
// present check, and Detail says why a check was held or skipped.
type Result struct {
	Item   Item
	Status Status
	File   string
	Rego   string
	Detail string
}

// Deliver delivers an answer into the repository at root. Every check is verified before anything is
// written: its digest must match its Rego, the Rego must pass the vet that ipso compile runs, a file in
// .ipso/checks must not hold other bytes, no path may be a symlink, every decision file must be valid, and
// the rewritten decision file must hold nothing but the one added check. A problem in any of them is
// returned, one line each, and nothing is written. The Rego files are written first and the decision files
// after, so a failure part way leaves only files that a second run accepts.
func Deliver(root string, cfg config.Config, answer Answer, now time.Time) ([]Result, []string, error) {
	loaded, problems, err := edr.Load(root, cfg.Decisions)
	if err != nil {
		return nil, nil, err
	}
	if len(problems) > 0 {
		return nil, problems, nil
	}
	repo, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = repo.Close() }()

	byID := map[string][]edr.Loaded{}
	for _, item := range loaded {
		byID[item.Rec.ID] = append(byID[item.Rec.ID], item)
	}
	inForce := map[string]edr.Loaded{}
	for id, files := range byID {
		for _, file := range files {
			if !file.Rec.InForce(now) {
				continue
			}
			if prev, ok := inForce[id]; ok {
				problems = append(problems, fmt.Sprintf("%s: duplicate-id: %s", file.Shown, prev.Shown))
				continue
			}
			inForce[id] = file
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return nil, problems, nil
	}

	texts := map[string]string{}
	changed := map[string]bool{}
	var newRego []Result
	results := make([]Result, 0, len(answer.AcceptedChecks))
	for _, item := range answer.AcceptedChecks {
		result := Result{Item: item}
		switch {
		case item.held():
			result.Status = Held
			result.Detail = fmt.Sprintf("it was accepted for version %d of its decision and version %d is in force", item.DecisionVersion, item.VersionInForce)
		case item.EDRID == nil:
			result.Status = Skipped
			result.Detail = "its decision has no EDR id"
		default:
			file, ok := inForce[*item.EDRID]
			if !ok {
				result.Status = Skipped
				result.Detail = fmt.Sprintf("no decision file in force here has the id %s", *item.EDRID)
				if len(byID[*item.EDRID]) == 0 {
					result.Detail = fmt.Sprintf("no decision file here has the id %s", *item.EDRID)
				}
				break
			}
			result.File = file.Shown
			result.Rego = path.Join(Dir, item.ID+".rego")
			wrote, problem := plan(repo, root, &result, item, file, texts, changed)
			if problem != "" {
				problems = append(problems, problem)
				break
			}
			result.Status = Present
			if wrote.entry || wrote.rego {
				result.Status = Added
			}
			if wrote.rego {
				newRego = append(newRego, result)
			}
		}
		results = append(results, result)
	}
	if len(problems) > 0 {
		return results, problems, nil
	}

	for _, result := range newRego {
		if err := writeNew(repo, result.Rego, *result.Item.Rego); err != nil {
			return results, nil, fmt.Errorf("write %s: %w", result.Rego, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(changed)) {
		if err := replace(repo, name, texts[name]); err != nil {
			return results, nil, fmt.Errorf("write %s: %w", name, err)
		}
	}
	return results, nil, nil
}

type writes struct{ rego, entry bool }

// plan verifies one deliverable check and folds its entry into the text of its decision file. It returns a
// problem and no writes when the check must stop the whole delivery.
func plan(repo *os.Root, root string, result *Result, item Item, file edr.Loaded, texts map[string]string, changed map[string]bool) (writes, string) {
	rego := []byte(*item.Rego)
	sum := sha256.Sum256(rego)
	if hex.EncodeToString(sum[:]) != *item.RegoSHA256 {
		return writes{}, fmt.Sprintf("check %s: the digest does not match the rego", item.ID)
	}
	if _, err := rulecheck.Compile(rego); err != nil {
		return writes{}, fmt.Sprintf("check %s: %s: %s", item.ID, rulecheck.Code(err), err)
	}
	for _, name := range []string{result.Rego, file.Shown} {
		if err := rules.RefuseSymlinks(repo, name); err != nil {
			return writes{}, fmt.Sprintf("check %s: %s", item.ID, err)
		}
	}
	var out writes
	existing, err := repo.ReadFile(result.Rego)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.rego = true
	case err != nil:
		return writes{}, fmt.Sprintf("check %s: read %s: %s", item.ID, result.Rego, err)
	case string(existing) != *item.Rego:
		return writes{}, fmt.Sprintf("check %s: %s exists with other contents, and delivery never replaces a file", item.ID, result.Rego)
	}
	text, ok := texts[file.Shown]
	if !ok {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Shown)))
		if err != nil {
			return writes{}, fmt.Sprintf("%s: %s", file.Shown, err)
		}
		text = string(raw)
	}
	next, added, err := edr.AddCheck(text, edr.Check{Engine: "opa", Target: "agent-edit", Ref: result.Rego})
	if err != nil {
		return writes{}, fmt.Sprintf("%s: check %s: %s", file.Shown, item.ID, err)
	}
	texts[file.Shown] = next
	if added {
		out.entry = true
		changed[file.Shown] = true
	}
	return out, ""
}

// writeNew creates the file and its directories. It never replaces a file.
func writeNew(repo *os.Root, name, text string) error {
	if err := repo.MkdirAll(path.Dir(name), 0o755); err != nil {
		return err
	}
	file, err := repo.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = file.WriteString(text)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

// replace writes the file through a temporary file in its directory, with the mode the file had.
func replace(repo *os.Root, name, text string) error {
	info, err := repo.Stat(name)
	if err != nil {
		return err
	}
	temp := name + ".ipso-tmp"
	if err := repo.Remove(temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := repo.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, err = file.WriteString(text)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		// The umask narrowed the mode at creation, and the file keeps the mode it had.
		err = repo.Chmod(temp, info.Mode().Perm())
	}
	if err == nil {
		err = repo.Rename(temp, name)
	}
	if err != nil {
		_ = repo.Remove(temp)
	}
	return err
}
