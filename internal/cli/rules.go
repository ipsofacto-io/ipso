package cli

import (
	"io"
	"os"
	"slices"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/rules"
)

const rulesUsage = "usage: ipso rules generate|check"

func rulesCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) != 1 || (args[0] != "generate" && args[0] != "check") {
		fprintln(stderr, rulesUsage)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	decisions, ok := loadRuleDecisions(root, cfg, d.now(), stdout, stderr)
	if !ok {
		return 1
	}
	repo, err := os.OpenRoot(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	defer func() { _ = repo.Close() }()

	changes, err := rules.Plan(repo, decisions, cfg.Decisions)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if args[0] == "check" {
		for _, change := range changes {
			fprintf(stdout, "%s: out of date\n", compiler.EscapeControls(change.Path))
		}
		if len(changes) > 0 {
			fprintln(stdout, "run ipso rules generate")
			return 1
		}
		fprintln(stdout, "rules files are up to date")
		return 0
	}
	if err := rules.Apply(repo, changes); err != nil {
		fprintln(stderr, err)
		return 1
	}
	for _, change := range changes {
		if change.Remove {
			fprintf(stdout, "removed %s\n", compiler.EscapeControls(change.Path))
			continue
		}
		fprintf(stdout, "wrote %s\n", compiler.EscapeControls(change.Path))
	}
	if len(changes) == 0 {
		fprintln(stdout, "rules files are up to date")
	}
	return 0
}

// loadRuleDecisions returns the records in force. Any invalid file stops the command.
func loadRuleDecisions(root string, cfg config.Config, now time.Time, stdout, stderr io.Writer) ([]rules.Decision, bool) {
	loaded, problems, err := edr.LoadInForce(root, cfg.Decisions, now)
	if err != nil {
		fprintln(stderr, err)
		return nil, false
	}
	for _, problem := range problems {
		fprintln(stdout, compiler.EscapeControls(problem))
	}
	if len(problems) > 0 {
		return nil, false
	}
	decisions := make([]rules.Decision, 0, len(loaded))
	for _, item := range loaded {
		text, ok := edr.DecisionText(item.Doc.Body)
		if !ok {
			fprintf(stdout, "%s: missing heading ## Decision\n", compiler.EscapeControls(item.Shown))
			return nil, false
		}
		decisions = append(decisions, ruleDecision(item.Doc, item.Rec, item.Shown, text))
	}
	return decisions, true
}

func ruleDecision(doc edr.Document, rec edr.Record, shown, text string) rules.Decision {
	item := rules.Decision{
		Slug:        rec.Slug,
		Title:       doc.Title(),
		Status:      rec.Status,
		Criticality: rec.Criticality,
		Record:      shown,
		Statement:   text,
		Sensitive:   slices.Contains(rec.Tags, rules.SensitiveTag),
	}
	repoWide := false
	allEnv := false
	for _, scope := range rec.Scope {
		if len(scope.Paths) == 0 {
			repoWide = true
		}
		if len(scope.Env) == 0 {
			allEnv = true
		}
		item.Paths = appendNew(item.Paths, scope.Paths)
		item.Env = appendNew(item.Env, scope.Env)
	}
	if repoWide {
		item.Paths = nil
	}
	if allEnv {
		item.Env = nil
	}
	return item
}

func appendNew(list, values []string) []string {
	for _, value := range values {
		if !slices.Contains(list, value) {
			list = append(list, value)
		}
	}
	return list
}
