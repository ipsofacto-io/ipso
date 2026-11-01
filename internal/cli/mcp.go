package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edit"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/rules"
	"github.com/ipsofacto-io/ipso/internal/sarif"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const mcpUsage = "usage: ipso mcp"

// mcpCmd serves the MCP tools over stdio for one checkout until the client closes the stream.
// Stdout carries the protocol, so nothing else may write to it.
func mcpCmd(root string, args []string, stderr io.Writer, d deps) int {
	if len(args) != 0 {
		fprintln(stderr, mcpUsage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := mcptools.NewServer(Version, newLocalBackend(root, d))
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		fprintln(stderr, err)
		return 1
	}
	return 0
}

// localBackend answers the tools from the files of one checkout. It makes no network call.
type localBackend struct {
	root string
	d    deps
}

func newLocalBackend(root string, d deps) *localBackend {
	if d.now == nil {
		d.now = time.Now
	}
	return &localBackend{root: root, d: d}
}

func (b *localBackend) Applicable(_ context.Context, in mcptools.ApplicableInput) (mcptools.ApplicableOutput, error) {
	paths, err := b.relativePaths(in.Paths)
	if err != nil {
		return mcptools.ApplicableOutput{}, err
	}
	cfg, _, err := config.Load(b.root)
	if err != nil {
		return mcptools.ApplicableOutput{}, err
	}
	loaded, problems, err := edr.LoadInForce(b.root, cfg.Decisions, b.d.now())
	if err != nil {
		return mcptools.ApplicableOutput{}, err
	}
	// A partial list would read as "nothing else applies".
	if len(problems) > 0 {
		return mcptools.ApplicableOutput{}, fmt.Errorf("invalid decision files: %s", compiler.EscapeControls(strings.Join(problems, "; ")))
	}
	out := mcptools.ApplicableOutput{Decisions: []mcptools.Decision{}}
	for _, item := range loaded {
		if item.Rec.Applies(in.Repo, paths, in.Env) {
			decision := toolDecision(item)
			text, _ := edr.DecisionText(item.Doc.Body)
			if !decision.Sensitive {
				decision.Statement = rules.Statement(text)
			}
			out.Decisions = append(out.Decisions, decision)
		}
	}
	return out, nil
}

func (b *localBackend) Get(_ context.Context, in mcptools.GetInput) (mcptools.GetOutput, error) {
	if in.Ref == "" {
		return mcptools.GetOutput{}, errors.New("ref is required")
	}
	if in.AsOfTx != "" {
		return mcptools.GetOutput{}, errors.New("as_of_tx needs a registry, and the local server reads files")
	}
	when := b.d.now()
	if in.AsOfValid != "" {
		parsed, err := time.Parse("2006-01-02", in.AsOfValid)
		if err != nil {
			return mcptools.GetOutput{}, errors.New("as_of_valid must be YYYY-MM-DD")
		}
		when = parsed
	}
	cfg, _, err := config.Load(b.root)
	if err != nil {
		return mcptools.GetOutput{}, err
	}
	loaded, _, err := edr.Load(b.root, cfg.Decisions)
	if err != nil {
		return mcptools.GetOutput{}, err
	}
	var found []edr.Loaded
	for _, item := range loaded {
		if item.Rec.ID == in.Ref || item.Rec.Slug == in.Ref {
			found = append(found, item)
		}
	}
	switch len(found) {
	case 0:
		return mcptools.GetOutput{}, fmt.Errorf("no decision with id or slug %q", compiler.EscapeControls(in.Ref))
	case 1:
	default:
		return mcptools.GetOutput{}, fmt.Errorf("more than one decision with id or slug %q", compiler.EscapeControls(in.Ref))
	}
	decision := toolDecision(found[0])
	out := mcptools.GetOutput{Decision: decision, InForce: found[0].Rec.InForce(when)}
	if !decision.Sensitive {
		text, _ := edr.DecisionText(found[0].Doc.Body)
		out.Decision.Statement = strings.TrimSpace(text)
		out.Body = found[0].Doc.Body
	}
	return out, nil
}

func (b *localBackend) Evaluate(_ context.Context, in mcptools.EvaluateInput) (mcptools.EvaluateOutput, error) {
	if (in.Diff == "") == (in.Plan == "") {
		return mcptools.EvaluateOutput{}, errors.New("give exactly one of diff and plan")
	}
	build, err := compiler.LoadBuild(b.root)
	if err != nil {
		return mcptools.EvaluateOutput{}, fmt.Errorf("%w. Run ipso compile", err)
	}
	if in.Plan != "" {
		return b.evaluatePlan(in, build)
	}
	return b.evaluateDiff(in, build)
}

// evaluatePlan goes through ipso check plan on a private temporary file, so the rules stay one.
func (b *localBackend) evaluatePlan(in mcptools.EvaluateInput, build compiler.Build) (mcptools.EvaluateOutput, error) {
	dir, err := os.MkdirTemp("", "ipso-mcp-")
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	planFile := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planFile, []byte(in.Plan), 0o600); err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	sarifFile := filepath.Join(dir, "results.sarif")
	args := []string{"check", "plan", planFile, "--sarif", sarifFile}
	if in.Env != "" {
		args = append(args, "--env", in.Env)
	}
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, b.d)
	if code == 2 || stderr.Len() > 0 {
		return mcptools.EvaluateOutput{}, errors.New(compiler.EscapeControls(strings.TrimSpace(stderr.String())))
	}
	results, err := os.ReadFile(sarifFile)
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	return mcptools.EvaluateOutput{
		Blocked:      code != 0,
		Lines:        outputLines(stdout.String()),
		SARIF:        string(results),
		NotEvaluated: notEvaluated(build, "terraform-plan"),
	}, nil
}

func (b *localBackend) evaluateDiff(in mcptools.EvaluateInput, build compiler.Build) (mcptools.EvaluateOutput, error) {
	repo, err := os.OpenRoot(b.root)
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	defer func() { _ = repo.Close() }()
	proposals, err := edit.FromDiff(repo, in.Diff)
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	results, err := edit.Evaluate(build, proposals, in.Env, b.d.now())
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	var lines bytes.Buffer
	blocked := false
	checks := make([]sarif.Check, 0, len(results))
	for _, result := range results {
		_, hard := verdictOf(&lines, result.Entry, result.Outcome)
		blocked = blocked || hard
		checks = append(checks, sarif.Check{Entry: result.Entry, Outcome: result.Outcome})
	}
	log, err := sarif.Marshal(Version, sarif.Category(edit.Target, in.Env, ""), checks)
	if err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	return mcptools.EvaluateOutput{
		Blocked:      blocked,
		Lines:        outputLines(lines.String()),
		SARIF:        string(log),
		NotEvaluated: notEvaluated(build, edit.Target),
	}, nil
}

func (b *localBackend) Propose(_ context.Context, in mcptools.ProposeInput) (mcptools.ProposeOutput, error) {
	for _, glob := range in.Paths {
		if err := rules.CheckGlob(glob); err != nil {
			return mcptools.ProposeOutput{}, err
		}
	}
	id, slug, text, err := edr.NewProposal(edr.ProposalInput{
		Title:        in.Title,
		Statement:    in.Statement,
		Rationale:    in.Rationale,
		Verification: in.Verification,
		Paths:        in.Paths,
		Env:          in.Env,
		SessionRef:   in.SessionRef,
	}, b.d.now())
	if err != nil {
		return mcptools.ProposeOutput{}, err
	}
	cfg, _, err := config.Load(b.root)
	if err != nil {
		return mcptools.ProposeOutput{}, err
	}
	name, err := proposalPath(cfg.Decisions, slug)
	if err != nil {
		return mcptools.ProposeOutput{}, err
	}
	if err := writeNewFile(b.root, name, text); err != nil {
		return mcptools.ProposeOutput{}, err
	}
	return mcptools.ProposeOutput{ProposalID: id, Status: "proposed", Location: name}, nil
}

// proposalPath picks a path a decisions glob matches, so ipso check reads the proposal. It prefers
// a proposed directory, which keeps proposals apart in review.
func proposalPath(globs []string, slug string) (string, error) {
	for _, glob := range globs {
		var literal []string
		for _, segment := range strings.Split(glob, "/") {
			if strings.ContainsAny(segment, "*?") {
				break
			}
			literal = append(literal, segment)
		}
		base := strings.Join(literal, "/")
		for _, candidate := range []string{base + "/proposed/" + slug + ".md", base + "/" + slug + ".md"} {
			candidate = strings.TrimPrefix(candidate, "/")
			if edr.MatchPath(glob, candidate) {
				return candidate, nil
			}
		}
	}
	return "", errors.New("no decisions glob in the config can hold a proposal")
}

// writeNewFile never replaces a file and never follows a link.
func writeNewFile(root, name, text string) error {
	repo, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = repo.Close() }()
	if err := rules.RefuseSymlinks(repo, name); err != nil {
		return err
	}
	if err := repo.MkdirAll(filepath.ToSlash(filepath.Dir(name)), 0o755); err != nil {
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

// relativePaths accepts paths from the root or absolute paths inside it. A path outside the
// checkout is an error, because no decision here could speak for it.
func (b *localBackend) relativePaths(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, name := range paths {
		rel, err := repoRelative(b.root, name)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

func repoRelative(root, name string) (string, error) {
	rel := filepath.FromSlash(name)
	if filepath.IsAbs(rel) {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", err
		}
		if !isWithin(root, rel) && !isWithin(resolvedRoot, rel) {
			return "", fmt.Errorf("%q is outside the repository", compiler.EscapeControls(name))
		}
		base := root
		if !isWithin(root, rel) {
			base = resolvedRoot
		}
		if rel, err = filepath.Rel(base, rel); err != nil {
			return "", err
		}
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%q is outside the repository", compiler.EscapeControls(name))
	}
	return rel, nil
}

func isWithin(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func toolDecision(item edr.Loaded) mcptools.Decision {
	sensitive := slices.Contains(item.Rec.Tags, rules.SensitiveTag)
	decision := mcptools.Decision{
		ID:          item.Rec.ID,
		Slug:        item.Rec.Slug,
		Status:      item.Rec.Status,
		State:       rules.BrandState(item.Rec.Status),
		Criticality: item.Rec.Criticality,
		Record:      item.Shown,
		Sources:     []string{},
		Paths:       []string{},
		Sensitive:   sensitive,
		Checks:      []mcptools.Check{},
	}
	if !sensitive {
		decision.Title = item.Doc.Title()
		for _, source := range item.Doc.Sources() {
			decision.Sources = append(decision.Sources, source.URL)
		}
	}
	wide := false
	for _, scope := range item.Rec.Scope {
		wide = wide || len(scope.Paths) == 0
		decision.Paths = appendNew(decision.Paths, scope.Paths)
	}
	if wide {
		decision.Paths = []string{}
	}
	for _, check := range item.Rec.Checks {
		mode, err := check.EffectiveMode(item.Rec.Criticality)
		if err != nil {
			mode = "unknown"
		}
		decision.Checks = append(decision.Checks, mcptools.Check{Engine: check.Engine, Target: check.Target, Mode: mode})
	}
	return decision
}

func notEvaluated(build compiler.Build, target string) []string {
	out := []string{}
	for _, entry := range build.Entries {
		if entry.Target != target {
			out = append(out, fmt.Sprintf("%s: checks[%d] (%s)", entry.Slug, entry.CheckIndex, entry.Engine))
		}
	}
	return out
}

func outputLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
