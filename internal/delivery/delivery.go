// Package delivery brings the accepted checks of a control plane into a repository (ADR-0120, ADR-0158,
// ADR-0165). For each check it writes the Rego (.rego) or LLM check specification (.llm.json) under
// .ipso/checks, which the agent hooks protect, and adds one entry to the checks of the decision file that
// holds the EDR id the answer names. A built-in template check has no file: its entry is the ref ipso:<id>.
// ipso compile then builds it like any repository check.
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
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
	"github.com/ipsofacto-io/ipso/pkg/templates"
)

// Dir is where the artifact of a delivered check is written.
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

// Item is one accepted check as the control plane serves it. Engine defaults to "opa" when omitted so
// ADR-0120 payloads decode unchanged. Engine "llm" carries LLMSpec and LLMSpecSHA256 instead of Rego. A
// built-in template check carries Ref, ipso:<id>, and no payload; its engine is "opa" with target
// "terraform-plan" or "semgrep" with no target.
type Item struct {
	ID              string  `json:"id"`
	DecisionID      string  `json:"decision_id"`
	EDRID           *string `json:"edr_id"`
	DecisionVersion int     `json:"decision_version"`
	VersionInForce  int     `json:"version_in_force"`
	Engine          string  `json:"engine,omitempty"`
	Target          string  `json:"target,omitempty"`
	Mode            string  `json:"mode,omitempty"`
	MaxAgeDays      int     `json:"max_age_days,omitempty"`
	Rego            *string `json:"rego"`
	RegoSHA256      *string `json:"rego_sha256"`
	LLMSpec         *string `json:"llm_spec,omitempty"`
	LLMSpecSHA256   *string `json:"llm_spec_sha256,omitempty"`
	Ref             *string `json:"ref,omitempty"`
}

// Answer is the body of GET /v1/accepted-checks.
type Answer struct {
	AcceptedChecks []Item `json:"accepted_checks"`
}

// held reports whether the check was accepted for a version that is not in force. It is never delivered.
func (i Item) held() bool { return i.DecisionVersion != i.VersionInForce }

func (i Item) effectiveEngine() string {
	if i.Engine == "" {
		return "opa"
	}
	return i.Engine
}

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
	case i.MaxAgeDays < 0 || i.MaxAgeDays > 365:
		return errors.New("max_age_days is out of 1..365")
	case i.Mode != "" && i.Mode != "block" && i.Mode != "warn" && i.Mode != "advise":
		return fmt.Errorf("unsupported mode %q", i.Mode)
	}
	eng := i.effectiveEngine()
	if eng != "opa" && eng != "llm" && eng != "semgrep" {
		return fmt.Errorf("unsupported engine %q", eng)
	}
	if i.held() {
		return nil
	}
	if i.Ref != nil || eng == "semgrep" {
		return i.validateTemplate()
	}
	if eng == "llm" {
		switch {
		case i.LLMSpec == nil || i.LLMSpecSHA256 == nil:
			return errors.New("an llm check for the version in force carries its llm_spec and its digest")
		case len(*i.LLMSpec) > llmcheck.MaxSpecBytes:
			return fmt.Errorf("llm_spec is over %d bytes", llmcheck.MaxSpecBytes)
		case !digestPattern.MatchString(*i.LLMSpecSHA256):
			return errors.New("llm_spec_sha256 is not 64 lowercase hex digits")
		}
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

// validateTemplate checks a template item against the catalog this ipso is built with, so an id the
// server knows and this version does not stops the delivery instead of writing an entry ipso compile refuses.
func (i Item) validateTemplate() error {
	switch {
	case i.Ref == nil:
		return errors.New("a semgrep check for the version in force carries a template ref")
	case i.Rego != nil || i.RegoSHA256 != nil || i.LLMSpec != nil || i.LLMSpecSHA256 != nil:
		return errors.New("a template check carries a ref and no rego or llm_spec")
	}
	tmpl, ok := templates.Lookup(*i.Ref)
	if !ok {
		return fmt.Errorf("%s: the ref %q is not a template of this ipso version, which may be older than the server", compiler.CodeTemplateUnknown, *i.Ref)
	}
	if i.effectiveEngine() != tmpl.Engine || i.Target != tmpl.Target {
		return fmt.Errorf("the template %s is engine %q with target %q, not engine %q with target %q", tmpl.Ref, tmpl.Engine, tmpl.Target, i.effectiveEngine(), i.Target)
	}
	return nil
}

// Status is what happened to one check.
type Status string

const (
	// Added: the check artifact or the entry was written.
	Added Status = "added"
	// Present: the check artifact and the entry were already there, and nothing was written.
	Present Status = "present"
	// Held: accepted for a version of its decision that is not in force, so it was not delivered.
	Held Status = "held"
	// Skipped: no decision file in this checkout, in force, holds the EDR id of its decision.
	Skipped Status = "skipped"
)

// Result is the outcome for one check, in the order of the answer. File is the decision file of an added or
// present check, Rego is the delivered artifact path under .ipso/checks or the ref of a template check, and
// Detail says why a check was held or skipped.
type Result struct {
	Item   Item
	Status Status
	File   string
	Rego   string
	Detail string
}

// Deliver delivers an answer into the repository at root. Every check is verified before anything is
// written: its digest must match its payload, the payload must pass the vet that ipso compile runs, a file in
// .ipso/checks must not hold other bytes, no path may be a symlink, every decision file must be valid, and
// the rewritten decision file must hold nothing but the one added check.
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
	type pendingArtifact struct {
		path    string
		content string
	}
	var newArtifacts []pendingArtifact
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
			switch {
			case item.Ref != nil:
				result.Rego = *item.Ref
			case item.effectiveEngine() == "llm":
				result.Rego = path.Join(Dir, item.ID+".llm.json")
			default:
				result.Rego = path.Join(Dir, item.ID+".rego")
			}
			wrote, content, problem := plan(repo, root, &result, item, file, texts, changed)
			if problem != "" {
				problems = append(problems, problem)
				break
			}
			result.Status = Present
			if wrote.entry || wrote.artifact {
				result.Status = Added
			}
			if wrote.artifact {
				newArtifacts = append(newArtifacts, pendingArtifact{path: result.Rego, content: content})
			}
		}
		results = append(results, result)
	}
	if len(problems) > 0 {
		return results, problems, nil
	}

	for _, art := range newArtifacts {
		if err := writeNew(repo, art.path, art.content); err != nil {
			return results, nil, fmt.Errorf("write %s: %w", art.path, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(changed)) {
		if err := replace(repo, name, texts[name]); err != nil {
			return results, nil, fmt.Errorf("write %s: %w", name, err)
		}
	}
	return results, nil, nil
}

type writes struct{ artifact, entry bool }

// plan verifies one deliverable check and folds its entry into the text of its decision file.
func plan(repo *os.Root, root string, result *Result, item Item, file edr.Loaded, texts map[string]string, changed map[string]bool) (writes, string, string) {
	eng := item.effectiveEngine()
	var payload string
	var addCheck edr.Check
	if item.Ref != nil {
		// validateTemplate matched the ref, engine and target against the catalog of this build.
		if err := rules.RefuseSymlinks(repo, file.Shown); err != nil {
			return writes{}, "", fmt.Sprintf("check %s: %s", item.ID, err)
		}
		addCheck = edr.Check{Engine: eng, Target: item.Target, Ref: *item.Ref, MaxAgeDays: item.MaxAgeDays}
		return addEntry(root, file, item, addCheck, texts, changed)
	}
	if eng == "llm" {
		raw := []byte(*item.LLMSpec)
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != *item.LLMSpecSHA256 {
			return writes{}, "", fmt.Sprintf("check %s: the digest does not match the llm_spec", item.ID)
		}
		effMode, modeErr := (edr.Check{Mode: item.Mode}).EffectiveMode(file.Rec.Criticality)
		if modeErr != nil {
			return writes{}, "", fmt.Sprintf("check %s: %s", item.ID, modeErr)
		}
		requireBlock := effMode == "block"
		spec, err := llmcheck.ParseAndValidate(raw, item.Target, requireBlock)
		if err != nil {
			return writes{}, "", fmt.Sprintf("check %s: %s", item.ID, err)
		}
		payload = *item.LLMSpec
		addCheck = edr.Check{
			Engine:     "llm",
			Target:     spec.Target,
			Ref:        result.Rego,
			Mode:       item.Mode,
			MaxAgeDays: item.MaxAgeDays,
		}
	} else {
		rego := []byte(*item.Rego)
		sum := sha256.Sum256(rego)
		if hex.EncodeToString(sum[:]) != *item.RegoSHA256 {
			return writes{}, "", fmt.Sprintf("check %s: the digest does not match the rego", item.ID)
		}
		if _, err := rulecheck.Compile(rego); err != nil {
			return writes{}, "", fmt.Sprintf("check %s: %s: %s", item.ID, rulecheck.Code(err), err)
		}
		payload = *item.Rego
		target := item.Target
		if target == "" {
			target = "agent-edit"
		}
		addCheck = edr.Check{
			Engine:     "opa",
			Target:     target,
			Ref:        result.Rego,
			MaxAgeDays: item.MaxAgeDays,
		}
	}
	for _, name := range []string{result.Rego, file.Shown} {
		if err := rules.RefuseSymlinks(repo, name); err != nil {
			return writes{}, "", fmt.Sprintf("check %s: %s", item.ID, err)
		}
	}
	var out writes
	existing, err := repo.ReadFile(result.Rego)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.artifact = true
	case err != nil:
		return writes{}, "", fmt.Sprintf("check %s: read %s: %s", item.ID, result.Rego, err)
	case string(existing) != payload:
		return writes{}, "", fmt.Sprintf("check %s: %s exists with other contents, and delivery never replaces a file", item.ID, result.Rego)
	}
	entry, _, problem := addEntry(root, file, item, addCheck, texts, changed)
	if problem != "" {
		return writes{}, "", problem
	}
	out.entry = entry.entry
	return out, payload, ""
}

// addEntry folds one check entry into the text of its decision file. An entry with the same ref is
// already there, so it adds nothing.
func addEntry(root string, file edr.Loaded, item Item, addCheck edr.Check, texts map[string]string, changed map[string]bool) (writes, string, string) {
	text, ok := texts[file.Shown]
	if !ok {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Shown)))
		if err != nil {
			return writes{}, "", fmt.Sprintf("%s: %s", file.Shown, err)
		}
		text = string(raw)
	}
	next, added, err := edr.AddCheck(text, addCheck)
	if err != nil {
		return writes{}, "", fmt.Sprintf("%s: check %s: %s", file.Shown, item.ID, err)
	}
	texts[file.Shown] = next
	if added {
		changed[file.Shown] = true
	}
	return writes{entry: added}, "", ""
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
	_, err = io.WriteString(file, text)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

// replace writes text to a temporary file next to name and renames it over name, keeping name's mode.
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
