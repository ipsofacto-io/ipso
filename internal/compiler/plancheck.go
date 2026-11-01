package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/ipsofacto-io/ipso/internal/edr"
)

const (
	// CodeBuildMissing means .ipso/build is absent or has no manifest.
	CodeBuildMissing = "build-missing"
	// CodeBuildDigest means an artifact does not match the digest in the manifest.
	CodeBuildDigest = "build-digest"
	// CodeBuildManifest means the manifest cannot be read or carries a field the evaluator cannot use.
	CodeBuildManifest = "build-manifest"

	planTarget = "terraform-plan"
	opaEngine  = "opa"
)

// Build is one compiled .ipso/build directory.
// Files holds the artifact bytes verified against the manifest, keyed by decision id and check index.
type Build struct {
	Root     string
	Manifest []byte
	Entries  []Entry
	Files    map[string]map[string][]byte
}

// SHA256 returns the digest of the manifest bytes.
func (b Build) SHA256() string {
	sum := sha256.Sum256(b.Manifest)
	return hex.EncodeToString(sum[:])
}

// LoadBuild reads .ipso/build and checks every artifact against its manifest digest.
// A symlink at .ipso/build is refused, and every manifest path must stay inside the build.
func LoadBuild(root string) (Build, error) {
	dir := filepath.Join(root, filepath.FromSlash(buildDir))
	if err := refuseSymlink(dir); err != nil {
		return Build{}, err
	}
	buildRoot, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return Build{}, &Error{Code: CodeBuildMissing, Err: fmt.Errorf("run ipso compile first")}
	}
	if err != nil {
		return Build{}, err
	}
	defer func() { _ = buildRoot.Close() }()
	raw, err := fs.ReadFile(buildRoot.FS(), "manifest.json")
	if errors.Is(err, fs.ErrNotExist) {
		return Build{}, &Error{Code: CodeBuildMissing, Err: fmt.Errorf("run ipso compile first")}
	}
	if err != nil {
		return Build{}, err
	}
	build, err := Materialize(raw, func(rel string) ([]byte, error) {
		return readArtifact(buildRoot.FS(), rel)
	})
	if err != nil {
		return Build{}, err
	}
	build.Root = dir
	return build, nil
}

// Materialize checks a manifest and the artifact bytes it names.
// open is called with the slash-separated path of each artifact.
func Materialize(manifest []byte, open func(rel string) ([]byte, error)) (Build, error) {
	if open == nil {
		return Build{}, &Error{Code: CodeBuildManifest, Err: fmt.Errorf("missing artifacts")}
	}
	var decoded manifestFile
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		return Build{}, &Error{Code: CodeBuildManifest, Err: err}
	}
	files := make(map[string]map[string][]byte, len(decoded.Entries))
	for _, entry := range decoded.Entries {
		if _, ok := files[entryKey(entry)]; ok {
			return Build{}, &Error{Code: CodeBuildManifest, Err: fmt.Errorf("decision %s check %d listed twice", entry.DecisionID, entry.CheckIndex)}
		}
		if err := entry.dates(); err != nil {
			return Build{}, &Error{Code: CodeBuildManifest, Err: err}
		}
		if err := entry.Baseline.validate(); err != nil {
			return Build{}, &Error{Code: CodeBuildManifest, Err: fmt.Errorf("decision %s check %d: %w", entry.DecisionID, entry.CheckIndex, err)}
		}
		if entry.Path != "" && !ValidRepoPath(entry.Path) {
			return Build{}, &Error{Code: CodeBuildManifest, Err: fmt.Errorf("decision %s path is not inside the repository", entry.DecisionID)}
		}
		got := make(map[string][]byte, len(entry.Artifacts))
		for _, artifact := range entry.Artifacts {
			rel, err := ArtifactRel(entry.DecisionID, entry.CheckIndex, artifact.Name)
			if err != nil {
				return Build{}, err
			}
			body, err := open(rel)
			if err != nil {
				return Build{}, &Error{Code: codeOfRead(err), Err: fmt.Errorf("%s/%d/%s: %w", entry.DecisionID, entry.CheckIndex, artifact.Name, err)}
			}
			if len(body) > MaxRefBytes {
				return Build{}, &Error{Code: CodeRefTooLarge, Err: fmt.Errorf("%s/%d/%s: artifact is %d bytes", entry.DecisionID, entry.CheckIndex, artifact.Name, len(body))}
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != artifact.SHA256 {
				return Build{}, &Error{Code: CodeBuildDigest, Err: fmt.Errorf("%s/%d/%s", entry.DecisionID, entry.CheckIndex, artifact.Name)}
			}
			got[artifact.Name] = append([]byte(nil), body...)
		}
		files[entryKey(entry)] = got
	}
	return Build{Manifest: append([]byte(nil), manifest...), Entries: decoded.Entries, Files: files}, nil
}

func readArtifact(build fs.FS, rel string) ([]byte, error) {
	info, err := fs.Stat(build, rel)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxRefBytes {
		return nil, fmt.Errorf("artifact is %d bytes", info.Size())
	}
	body, err := fs.ReadFile(build, rel)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxRefBytes {
		return nil, fmt.Errorf("artifact is %d bytes", len(body))
	}
	return body, nil
}

func codeOfRead(err error) string {
	if strings.Contains(err.Error(), "escapes from parent") {
		return CodeArtifactName
	}
	if strings.Contains(err.Error(), "artifact is") {
		return CodeRefTooLarge
	}
	return CodeBuildDigest
}

func entryKey(entry Entry) string {
	return fmt.Sprintf("%s/%d", entry.DecisionID, entry.CheckIndex)
}

// dates reports whether the entry carries dates the evaluator can use.
func (e Entry) dates() error {
	if _, err := time.Parse(dateLayout, e.ValidFrom); err != nil {
		return fmt.Errorf("valid_from %q", e.ValidFrom)
	}
	if e.ValidTo != nil {
		if _, err := time.Parse(dateLayout, *e.ValidTo); err != nil {
			return fmt.Errorf("valid_to %q", *e.ValidTo)
		}
	}
	for _, waiver := range e.Waivers {
		if _, err := time.Parse(dateLayout, waiver.ValidFrom); err != nil {
			return fmt.Errorf("waiver valid_from %q", waiver.ValidFrom)
		}
		if _, err := time.Parse(dateLayout, waiver.ValidTo); err != nil {
			return fmt.Errorf("waiver valid_to %q", waiver.ValidTo)
		}
	}
	return nil
}

// Artifacts returns a copy of the bytes LoadBuild verified. It does not read the build again.
func (b Build) Artifacts(entry Entry) (map[string][]byte, error) {
	cached, ok := b.Files[entryKey(entry)]
	if !ok {
		return nil, &Error{Code: CodeBuildDigest, Err: fmt.Errorf("decision %s check %d", entry.DecisionID, entry.CheckIndex)}
	}
	out := make(map[string][]byte, len(cached))
	for name, body := range cached {
		out[name] = append([]byte(nil), body...)
	}
	return out, nil
}

// Applies reports whether the decision is in force on the calendar date of now
// and env is empty or the decision names that environment.
func (e Entry) Applies(env string, now time.Time) bool {
	from, err := time.Parse(dateLayout, e.ValidFrom)
	if err != nil {
		return false
	}
	var to *time.Time
	if e.ValidTo != nil {
		parsed, err := time.Parse(dateLayout, *e.ValidTo)
		if err != nil {
			return false
		}
		to = &parsed
	}
	// Compile already dropped records that were not in force, so the status here only
	// satisfies the date rule.
	if !(edr.Record{Status: "accepted", ValidFrom: from, ValidTo: to}).InForce(now) {
		return false
	}
	if env == "" || e.Env == nil {
		return true
	}
	return contains(e.Env, env)
}

// Selected reports whether the entry is an in-force OPA check for a Terraform plan.
func (e Entry) Selected(env string, now time.Time) bool {
	return e.SelectedFor(planTarget, env, now)
}

// SelectedFor reports whether the entry is an in-force OPA check for target.
func (e Entry) SelectedFor(target, env string, now time.Time) bool {
	if e.Engine != opaEngine || e.Target != target {
		return false
	}
	return e.Applies(env, now)
}

// Violation is one denial from a check. The terminal prints it. The report stores only the count.
// Position is set by engines that report a place in a repository file, and SARIF is its only reader.
// Identity is the raw values that feed a baseline fingerprint (ADR-0059), and no output prints it.
// A nil Identity means the violation cannot be baselined. Baselined is set when a baseline covers it.
type Violation struct {
	Message   string
	Address   string
	Position  *Position
	Identity  []string
	Baselined bool
}

// Position is a place in a repository file. Path is slash-separated and relative to the repository root.
// Lines and columns start at 1. An end value of 0 means the engine did not report it.
type Position struct {
	Path        string
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
}

// MaxBaselineFingerprints is the most fingerprints one decision can hold (ADR-0052).
const MaxBaselineFingerprints = 100000

// ValidDigest reports whether value is 64 lowercase hex characters.
func ValidDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	return strings.Trim(value, "0123456789abcdef") == ""
}

func (b *ManifestBaseline) validate() error {
	if b == nil {
		return nil
	}
	if !ValidDigest(b.Salt) {
		return fmt.Errorf("baseline salt is not 64 lowercase hex characters")
	}
	if len(b.Fingerprints) > MaxBaselineFingerprints {
		return fmt.Errorf("baseline has more than %d fingerprints", MaxBaselineFingerprints)
	}
	seen := make(map[string]struct{}, len(b.Fingerprints))
	for _, digest := range b.Fingerprints {
		if !ValidDigest(digest) {
			return fmt.Errorf("baseline fingerprint is not 64 lowercase hex characters")
		}
		if _, ok := seen[digest]; ok {
			return fmt.Errorf("baseline repeats a fingerprint")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

// ValidRepoPath reports whether path is a clean slash-separated path inside the repository.
func ValidRepoPath(path string) bool {
	return path != "." && !strings.Contains(path, "\\") && fs.ValidPath(path)
}

// Outcome is the result of evaluating one check.
// Waived is set when violations were found and a waiver in force covers them.
type Outcome struct {
	Violations []Violation
	Waived     bool
	Err        error
}

// Cover applies an in-force waiver to violations. An error is never waived.
func Cover(entry Entry, outcome Outcome, now time.Time) Outcome {
	if outcome.Err != nil || len(outcome.Violations) == 0 {
		outcome.Waived = false
		return outcome
	}
	outcome.Waived = Waived(entry, now)
	return outcome
}

// Waived reports whether a waiver on the entry binds on the calendar date of now.
func Waived(entry Entry, now time.Time) bool {
	for _, waiver := range entry.Waivers {
		from, err := time.Parse(dateLayout, waiver.ValidFrom)
		if err != nil {
			continue
		}
		to, err := time.Parse(dateLayout, waiver.ValidTo)
		if err != nil {
			continue
		}
		if (edr.Waiver{ValidFrom: from, ValidTo: to}).InForce(now) {
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Verdict is the outcome of one evaluated check.
type Verdict struct {
	DecisionID string `json:"decision_id"`
	Slug       string `json:"slug"`
	CheckIndex int    `json:"check_index"`
	Mode       string `json:"mode"`
	Result     string `json:"result"`
	Violations int    `json:"violations"`
}

// PlanReport is the local verdict report. It carries counts and hashes, never plan contents.
type PlanReport struct {
	ReportVersion int       `json:"report_version"`
	IpsoVersion   string    `json:"ipso_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Env           string    `json:"env"`
	PlanSHA256    string    `json:"plan_sha256"`
	BuildSHA256   string    `json:"build_sha256"`
	Verdicts      []Verdict `json:"verdicts"`
}

// CIReport is the verdict report for ipso check ci.
type CIReport struct {
	ReportVersion  int       `json:"report_version"`
	IpsoVersion    string    `json:"ipso_version"`
	EvaluatedAt    time.Time `json:"evaluated_at"`
	Env            string    `json:"env"`
	CommitSHA      string    `json:"commit_sha"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	BuildSHA256    string    `json:"build_sha256"`
	Verdicts       []Verdict `json:"verdicts"`
}

// DepcruiseReport is the verdict report for ipso check depcruise.
// It carries the paths that were cruised and the dependency-cruiser version, never module paths or rule names.
type DepcruiseReport struct {
	ReportVersion    int       `json:"report_version"`
	IpsoVersion      string    `json:"ipso_version"`
	EvaluatedAt      time.Time `json:"evaluated_at"`
	Env              string    `json:"env"`
	Paths            []string  `json:"paths"`
	DepcruiseVersion string    `json:"depcruise_version"`
	BuildSHA256      string    `json:"build_sha256"`
	Verdicts         []Verdict `json:"verdicts"`
}

// SemgrepReport is the verdict report for ipso check semgrep.
// It carries the paths that were scanned and the Semgrep version, never rule ids or file paths.
type SemgrepReport struct {
	ReportVersion  int       `json:"report_version"`
	IpsoVersion    string    `json:"ipso_version"`
	EvaluatedAt    time.Time `json:"evaluated_at"`
	Env            string    `json:"env"`
	Paths          []string  `json:"paths"`
	SemgrepVersion string    `json:"semgrep_version"`
	BuildSHA256    string    `json:"build_sha256"`
	Verdicts       []Verdict `json:"verdicts"`
}

// ArchUnitReport is the verdict report for ipso check archunit.
// It carries the class directories that were checked and the ArchUnit version, never rule names or class names.
// ArchUnitVersion is empty when the jars were not run.
type ArchUnitReport struct {
	ReportVersion   int       `json:"report_version"`
	IpsoVersion     string    `json:"ipso_version"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
	Env             string    `json:"env"`
	Paths           []string  `json:"paths"`
	ArchUnitVersion string    `json:"archunit_version"`
	BuildSHA256     string    `json:"build_sha256"`
	Verdicts        []Verdict `json:"verdicts"`
}

// ImportLinterReport is the verdict report for ipso check importlinter.
// It carries the source directories that were checked and the import-linter version, never contract names or module names.
// ImportLinterVersion is empty when python was not run.
type ImportLinterReport struct {
	ReportVersion       int       `json:"report_version"`
	IpsoVersion         string    `json:"ipso_version"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	Env                 string    `json:"env"`
	Paths               []string  `json:"paths"`
	ImportLinterVersion string    `json:"importlinter_version"`
	BuildSHA256         string    `json:"build_sha256"`
	Verdicts            []Verdict `json:"verdicts"`
}

// KyvernoReport is the verdict report for ipso check kyverno.
// It carries the paths that were checked and the Kyverno version, never policy names, resource names, or messages.
// KyvernoVersion is empty when the binary was not run.
type KyvernoReport struct {
	ReportVersion  int       `json:"report_version"`
	IpsoVersion    string    `json:"ipso_version"`
	EvaluatedAt    time.Time `json:"evaluated_at"`
	Env            string    `json:"env"`
	Paths          []string  `json:"paths"`
	KyvernoVersion string    `json:"kyverno_version"`
	BuildSHA256    string    `json:"build_sha256"`
	Verdicts       []Verdict `json:"verdicts"`
}

// GatekeeperReport is the verdict report for ipso check gatekeeper.
// It carries the paths that were checked and the gator version, never constraint names, object names, or messages.
// GatorVersion is empty when gator was not run.
type GatekeeperReport struct {
	ReportVersion int       `json:"report_version"`
	IpsoVersion   string    `json:"ipso_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Env           string    `json:"env"`
	Paths         []string  `json:"paths"`
	GatorVersion  string    `json:"gator_version"`
	BuildSHA256   string    `json:"build_sha256"`
	Verdicts      []Verdict `json:"verdicts"`
}

// ESLintReport is the verdict report for ipso check eslint.
// It carries the paths that were linted and the ESLint version, never rule ids, file paths, or messages.
// ESLintVersion is empty when eslint was not run.
type ESLintReport struct {
	ReportVersion int       `json:"report_version"`
	IpsoVersion   string    `json:"ipso_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Env           string    `json:"env"`
	Paths         []string  `json:"paths"`
	ESLintVersion string    `json:"eslint_version"`
	BuildSHA256   string    `json:"build_sha256"`
	Verdicts      []Verdict `json:"verdicts"`
}

// CheckovReport is the verdict report for ipso check checkov.
type CheckovReport struct {
	ReportVersion  int       `json:"report_version"`
	IpsoVersion    string    `json:"ipso_version"`
	EvaluatedAt    time.Time `json:"evaluated_at"`
	Env            string    `json:"env"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	BuildSHA256    string    `json:"build_sha256"`
	Verdicts       []Verdict `json:"verdicts"`
}

// AdapterReport is the verdict report for the checks that read another tool's plan or template.
// It carries the hash of the input as read, never resource names, values, or messages.
type AdapterReport struct {
	ReportVersion int       `json:"report_version"`
	IpsoVersion   string    `json:"ipso_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Env           string    `json:"env"`
	Adapter       string    `json:"adapter"`
	InputSHA256   string    `json:"input_sha256"`
	BuildSHA256   string    `json:"build_sha256"`
	Verdicts      []Verdict `json:"verdicts"`
}

// Judge turns the outcome of one check into its verdict. hard is true when a block-mode check has a
// violation that nothing covers, or when the check failed to evaluate. It is the one rule behind exit 1.
func Judge(entry Entry, outcome Outcome) (verdict Verdict, hard bool) {
	verdict = Verdict{
		DecisionID: entry.DecisionID,
		Slug:       entry.Slug,
		CheckIndex: entry.CheckIndex,
		Mode:       entry.Mode,
		Result:     "pass",
	}
	switch {
	case outcome.Err != nil:
		verdict.Result = "error"
		return verdict, true
	case len(outcome.Violations) > 0 && outcome.Waived:
		verdict.Result = "waived"
		verdict.Violations = len(outcome.Violations)
		return verdict, false
	case len(outcome.Violations) > 0:
		covered := outcome.Baselined()
		if covered == len(outcome.Violations) {
			verdict.Result = "waived"
			verdict.Violations = covered
			return verdict, false
		}
		verdict.Result = "fail"
		verdict.Violations = len(outcome.Violations) - covered
		return verdict, entry.Mode == "block"
	default:
		return verdict, false
	}
}

// Baselined counts the violations a baseline covers.
func (o Outcome) Baselined() int {
	covered := 0
	for _, violation := range o.Violations {
		if violation.Baselined {
			covered++
		}
	}
	return covered
}

// ReportVersion is the report contract version.
const ReportVersion = 1

// MarshalReport encodes a plan report as deterministic JSON.
// evaluated_at is UTC with a trailing Z and no fractional seconds.
func MarshalReport(report PlanReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	return encodeReport(report)
}

// MarshalAdapterReport encodes an adapter report as deterministic JSON.
func MarshalAdapterReport(report AdapterReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	return encodeReport(report)
}

// MarshalCIReport encodes a CI evidence report as deterministic JSON.
func MarshalCIReport(report CIReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	return encodeReport(report)
}

// MarshalCheckovReport encodes a Checkov report as deterministic JSON.
func MarshalCheckovReport(report CheckovReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	return encodeReport(report)
}

// MarshalDepcruiseReport encodes a dependency-cruiser report as deterministic JSON.
func MarshalDepcruiseReport(report DepcruiseReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalSemgrepReport encodes a Semgrep report as deterministic JSON.
func MarshalSemgrepReport(report SemgrepReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalArchUnitReport encodes an ArchUnit report as deterministic JSON.
func MarshalArchUnitReport(report ArchUnitReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalImportLinterReport encodes an import-linter report as deterministic JSON.
func MarshalImportLinterReport(report ImportLinterReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalKyvernoReport encodes a Kyverno report as deterministic JSON.
func MarshalKyvernoReport(report KyvernoReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalGatekeeperReport encodes a Gatekeeper report as deterministic JSON.
func MarshalGatekeeperReport(report GatekeeperReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// MarshalESLintReport encodes an ESLint report as deterministic JSON.
func MarshalESLintReport(report ESLintReport) ([]byte, error) {
	report.EvaluatedAt, report.Verdicts = finishReport(report.EvaluatedAt, report.Verdicts)
	if report.Paths == nil {
		report.Paths = []string{}
	}
	return encodeReport(report)
}

// EscapeControls replaces control characters so a violation line stays on one line.
func EscapeControls(value string) string {
	var buf strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			fmt.Fprintf(&buf, "\\u%04x", r)
			continue
		}
		buf.WriteRune(r)
	}
	return buf.String()
}

func finishReport(evaluated time.Time, verdicts []Verdict) (time.Time, []Verdict) {
	evaluated = evaluated.UTC().Truncate(time.Second)
	if verdicts == nil {
		verdicts = []Verdict{}
	}
	sort.Slice(verdicts, func(i, j int) bool {
		if verdicts[i].DecisionID != verdicts[j].DecisionID {
			return verdicts[i].DecisionID < verdicts[j].DecisionID
		}
		return verdicts[i].CheckIndex < verdicts[j].CheckIndex
	})
	return evaluated, verdicts
}

func encodeReport(report any) ([]byte, error) {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
