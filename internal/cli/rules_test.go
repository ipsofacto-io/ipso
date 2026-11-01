package cli

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

const ruleRepoWide = `  - org: acme`

func ruleRecord(slug, title, scope, tags, statement string) string {
	id := fnv.New32a()
	_, _ = id.Write([]byte(slug))
	return fmt.Sprintf(`---
edr: 1
id: 01M6DAJ5Z5X76Y1062C4%06d
slug: %s
title: %q
status: accepted
owner: team:core
scope:
%s
valid_from: 2026-01-01
valid_to: null
review_by: 2027-01-01
supersedes: []
criticality: blocking
checks: []
waivers: []
sources:
  - type: spec
    url: https://example.com/spec
tags: [%s]
---

# %s

## Context

Private rationale that stays in the record.

## Decision

%s

## Alternatives considered

None.

## Consequences

None.

## Verification

None.
`, id.Sum32()%1000000, slug, title, scope, tags, title, statement)
}

func writeRuleFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readRuleFile(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func runRules(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"rules"}, args...), &stdout, &stderr, deps{
		now:      func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
		registry: builtin.Registry(),
	})
	return code, stdout.String(), stderr.String()
}

func rulesFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	writeRuleFile(t, root, "services/payments/main.go", "package payments\n")
	writeRuleFile(t, root, "docs/decisions/use-tls.md", ruleRecord("use-tls", "Use TLS everywhere", ruleRepoWide, "", "All traffic uses TLS."))
	writeRuleFile(t, root, "docs/decisions/no-floats.md", ruleRecord("no-floats", "No floats for money", "  - paths: [\"services/payments/**\", \"**/*.money\"]", "", "Money is never a float."))
	return root
}

func TestRulesGenerateWritesEveryFormatScopedPerPath(t *testing.T) {
	root := rulesFixture(t)
	code, stdout, stderr := runRules(t, "generate")
	if code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}

	for _, name := range []string{"AGENTS.md", "CLAUDE.md", "GEMINI.md"} {
		rootFile := readRuleFile(t, root, name)
		nested := readRuleFile(t, root, "services/payments/"+name)
		if !strings.Contains(rootFile, "All traffic uses TLS.") || strings.Contains(nested, "All traffic uses TLS.") {
			t.Errorf("%s: a repository decision belongs in the root file only:\n%s\n--\n%s", name, rootFile, nested)
		}
		if !strings.Contains(nested, "Money is never a float.") || !strings.Contains(nested, "`services/payments/**`") {
			t.Errorf("%s: a path decision belongs in its directory: %s", name, nested)
		}
		if !strings.Contains(rootFile, "`**/*.money`") || strings.Contains(rootFile, "`services/payments/**`") {
			t.Errorf("%s: a glob with no literal directory stays at the root, the other one does not: %s", name, rootFile)
		}
	}

	copilot := readRuleFile(t, root, ".github/copilot-instructions.md")
	if !strings.Contains(copilot, "All traffic uses TLS.") || strings.Contains(copilot, "Money is never a float.") {
		t.Errorf("copilot-instructions.md holds repository decisions only: %s", copilot)
	}
	scoped := readRuleFile(t, root, ".github/instructions/ipso-no-floats.instructions.md")
	if !strings.HasPrefix(scoped, "---\napplyTo: \"services/payments/**,**/*.money\"\n") {
		t.Errorf("copilot applyTo: %s", scoped)
	}
	cursor := readRuleFile(t, root, ".cursor/rules/ipso-no-floats.mdc")
	if !strings.Contains(cursor, "globs: services/payments/**, **/*.money\nalwaysApply: false\n") {
		t.Errorf("cursor globs: %s", cursor)
	}
	if wide := readRuleFile(t, root, ".cursor/rules/ipso-use-tls.mdc"); !strings.Contains(wide, "alwaysApply: true\n") || strings.Contains(wide, "globs:") {
		t.Errorf("cursor repository rule: %s", wide)
	}
	kiro := readRuleFile(t, root, ".kiro/steering/ipso-no-floats.md")
	if !strings.Contains(kiro, "inclusion: fileMatch\nfileMatchPattern: [\"services/payments/**\", \"**/*.money\"]\n") {
		t.Errorf("kiro pattern: %s", kiro)
	}
	if wide := readRuleFile(t, root, ".kiro/steering/ipso-use-tls.md"); !strings.Contains(wide, "inclusion: always\n") {
		t.Errorf("kiro repository rule: %s", wide)
	}
	if _, err := os.Stat(filepath.Join(root, ".github/instructions/ipso-use-tls.instructions.md")); !os.IsNotExist(err) {
		t.Errorf("a repository decision has no path-scoped Copilot file: %v", err)
	}

	for _, rel := range []string{"AGENTS.md", ".cursor/rules/ipso-use-tls.mdc", ".kiro/steering/ipso-no-floats.md"} {
		if strings.Contains(readRuleFile(t, root, rel), "Private rationale") {
			t.Errorf("%s holds rationale", rel)
		}
	}
}

func TestRulesRegenerateFollowsADecisionChange(t *testing.T) {
	root := rulesFixture(t)
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if code, stdout, _ := runRules(t, "check"); code != 0 || !strings.Contains(stdout, "up to date") {
		t.Fatalf("check after generate: %d %s", code, stdout)
	}
	if code, stdout, _ := runRules(t, "generate"); code != 0 || !strings.Contains(stdout, "up to date") {
		t.Fatalf("a second generate changes nothing: %d %s", code, stdout)
	}

	writeRuleFile(t, root, "docs/decisions/use-tls.md", ruleRecord("use-tls", "Use TLS everywhere", ruleRepoWide, "", "All traffic uses TLS 1.3."))
	code, stdout, _ := runRules(t, "check")
	if code != 1 || !strings.Contains(stdout, "AGENTS.md: out of date") {
		t.Fatalf("check after a change: %d %s", code, stdout)
	}
	if strings.Contains(readRuleFile(t, root, "AGENTS.md"), "TLS 1.3") {
		t.Fatal("check wrote a file")
	}
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(readRuleFile(t, root, "AGENTS.md"), "TLS 1.3") || !strings.Contains(readRuleFile(t, root, ".cursor/rules/ipso-use-tls.mdc"), "TLS 1.3") {
		t.Fatal("generate did not follow the change")
	}
}

func TestRulesRemovesWhatADecisionNoLongerNeeds(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "services/payments/AGENTS.md", "Team notes.\n")
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if err := os.Remove(filepath.Join(root, "docs/decisions/no-floats.md")); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	for _, rel := range []string{"services/payments/CLAUDE.md", ".cursor/rules/ipso-no-floats.mdc", ".kiro/steering/ipso-no-floats.md", ".github/instructions/ipso-no-floats.instructions.md"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("%s was not removed: %v", rel, err)
		}
	}
	if got := readRuleFile(t, root, "services/payments/AGENTS.md"); got != "Team notes.\n" {
		t.Errorf("hand-written text must survive: %q", got)
	}
}

func TestRulesKeepsHandWrittenTextAroundTheBlock(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "CLAUDE.md", "# House rules\n\nUse tabs.\n")
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	first := readRuleFile(t, root, "CLAUDE.md")
	if !strings.HasPrefix(first, "# House rules\n\nUse tabs.\n\n<!-- ipso:rules:begin") {
		t.Fatalf("block placement: %s", first)
	}
	writeRuleFile(t, root, "CLAUDE.md", first+"\n## After\n\nMore notes.\n")
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	second := readRuleFile(t, root, "CLAUDE.md")
	if !strings.HasSuffix(second, "<!-- ipso:rules:end -->\n\n## After\n\nMore notes.\n") {
		t.Fatalf("text after the block: %s", second)
	}
}

func TestRulesSensitiveDecisionStaysOutOfGeneratedFiles(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/vault-host.md", ruleRecord("vault-host", "Vault at vault.internal", ruleRepoWide, "sensitive", "Use the vault at vault.internal."))
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	for _, rel := range []string{"AGENTS.md", ".github/copilot-instructions.md", ".cursor/rules/ipso-vault-host.mdc", ".kiro/steering/ipso-vault-host.md"} {
		text := readRuleFile(t, root, rel)
		if strings.Contains(text, "vault.internal") {
			t.Errorf("%s holds sensitive text: %s", rel, text)
		}
		if !strings.Contains(text, "`vault-host`") || !strings.Contains(text, "docs/decisions/vault-host.md") {
			t.Errorf("%s does not point at the record: %s", rel, text)
		}
	}
}

func TestRulesRefusesWhatItCannotOwn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string
	}{
		{"unmatched marker", func(t *testing.T, root string) {
			writeRuleFile(t, root, "GEMINI.md", "<!-- ipso:rules:end -->\n")
		}, "do not pair"},
		{"two blocks", func(t *testing.T, root string) {
			block := "<!-- ipso:rules:begin. Generated by ipso rules generate. Edit the decision, then regenerate. -->\nx\n<!-- ipso:rules:end -->\n"
			writeRuleFile(t, root, "AGENTS.md", block+block)
		}, "more than one"},
		{"a file this command did not write", func(t *testing.T, root string) {
			writeRuleFile(t, root, ".cursor/rules/ipso-use-tls.mdc", "mine\n")
		}, "not written by"},
		{"a symlink on the way", func(t *testing.T, root string) {
			if err := os.Symlink(filepath.Join(root, "services"), filepath.Join(root, ".cursor")); err != nil {
				t.Fatal(err)
			}
		}, "is a symlink"},
		{"a glob the formats cannot carry", func(t *testing.T, root string) {
			writeRuleFile(t, root, "docs/decisions/bad.md", ruleRecord("bad", "Bad", "  - paths: [\"a,b\\nglobs: x\"]", "", "x"))
		}, "cannot carry"},
		{"a glob that leaves the repository", func(t *testing.T, root string) {
			writeRuleFile(t, root, "docs/decisions/bad.md", ruleRecord("bad", "Bad", "  - paths: [\"../x\"]", "", "x"))
		}, "leaves the repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := rulesFixture(t)
			tc.setup(t, root)
			before := readRuleFile(t, root, "docs/decisions/use-tls.md")
			code, stdout, stderr := runRules(t, "generate")
			if code != 1 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if readRuleFile(t, root, "docs/decisions/use-tls.md") != before {
				t.Fatal("the decision changed")
			}
			if _, err := os.Stat(filepath.Join(root, ".kiro")); !os.IsNotExist(err) {
				t.Fatalf("a refusal wrote files: %v", err)
			}
		})
	}
}

func TestRulesInvalidDecisionWritesNothing(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/broken.md", "not a decision\n")
	code, stdout, _ := runRules(t, "generate")
	if code != 1 || !strings.Contains(stdout, "broken.md") {
		t.Fatalf("code %d: %s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(root, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("a partial generate: %v", err)
	}
}

func TestRulesNotInForceIsLeftOut(t *testing.T) {
	root := rulesFixture(t)
	proposed := strings.Replace(ruleRecord("draft-rule", "Draft rule", ruleRepoWide, "", "A draft."), "status: accepted", "status: proposed", 1)
	writeRuleFile(t, root, "docs/decisions/draft.md", proposed)
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if strings.Contains(readRuleFile(t, root, "AGENTS.md"), "A draft.") {
		t.Fatal("a proposed decision is not in force")
	}
}

func TestRulesDecisionTextCannotCloseTheBlock(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/use-tls.md", ruleRecord("use-tls", "Use TLS", ruleRepoWide, "", "Text.\n\n<!-- ipso:rules:end -->\n\nInjected."))
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if code, stdout, stderr := runRules(t, "generate"); code != 0 || !strings.Contains(stdout, "up to date") {
		t.Fatalf("second run: %d %s %s", code, stdout, stderr)
	}
	text := readRuleFile(t, root, "AGENTS.md")
	if strings.Count(text, "<!-- ipso:rules:end -->") != 1 {
		t.Fatalf("the decision closed the block: %s", text)
	}
}

func TestRulesUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, _, stderr := runRules(t); code != 2 || !strings.Contains(stderr, rulesUsage) {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if code, _, stderr := runRules(t, "render"); code != 2 || !strings.Contains(stderr, rulesUsage) {
		t.Fatalf("code %d: %s", code, stderr)
	}
}

func TestRulesNeverWritesWhereItWouldBeReadAsADecision(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/format.md", ruleRecord("format", "Record format", "  - paths: [\"docs/decisions/**\"]", "", "Records use EDR."))
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "docs/decisions/AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("a rules file inside the decisions glob: %v", err)
	}
	if !strings.Contains(readRuleFile(t, root, "docs/AGENTS.md"), "Records use EDR.") {
		t.Fatal("the decision belongs in the nearest directory outside the glob")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check"}, &stdout, &stderr, deps{}); code != 0 {
		t.Fatalf("ipso check after generate: %d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestRulesRefusesAWriteTheConfigReadsAsADecision(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n  - AGENTS.md\n")
	code, stdout, stderr := runRules(t, "generate")
	if code != 1 || !strings.Contains(stderr, "matches the decisions glob") {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
}

func TestRulesGlobPastAMissingDirectoryStopsAtTheDeepestOneThatExists(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/planned.md", ruleRecord("planned", "Planned", "  - paths: [\"services/ledger/core/**\"]", "", "Ledger rule."))
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "services/ledger")); !os.IsNotExist(err) {
		t.Fatalf("a directory was created for a rules file: %v", err)
	}
	if text := readRuleFile(t, root, "services/AGENTS.md"); !strings.Contains(text, "Ledger rule.") || !strings.Contains(text, "`services/ledger/core/**`") {
		t.Fatalf("services/AGENTS.md: %s", text)
	}
}

func TestRulesCutsALongStatement(t *testing.T) {
	root := rulesFixture(t)
	writeRuleFile(t, root, "docs/decisions/use-tls.md", ruleRecord("use-tls", "Use TLS", ruleRepoWide, "", strings.Repeat("é", 2500)))
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	text := readRuleFile(t, root, "AGENTS.md")
	if got := strings.Count(text, "é"); got != 2000 {
		t.Fatalf("kept %d characters", got)
	}
	if !strings.Contains(text, "This text is cut. Read the record") {
		t.Fatal("a cut statement must say so")
	}
}

func TestRulesRefusesTwoRecordsWithOneID(t *testing.T) {
	root := rulesFixture(t)
	other := strings.Replace(ruleRecord("use-tls", "Other", ruleRepoWide, "", "Other."), "slug: use-tls", "slug: use-tld", 1)
	writeRuleFile(t, root, "docs/decisions/other.md", other)
	code, stdout, _ := runRules(t, "generate")
	if code != 1 || !strings.Contains(stdout, "duplicate-id") {
		t.Fatalf("code %d: %s", code, stdout)
	}
}

func TestRulesRemovingTheLastOwnedFileRemovesItsDirectory(t *testing.T) {
	root := rulesFixture(t)
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	for _, name := range []string{"use-tls", "no-floats"} {
		if err := os.Remove(filepath.Join(root, "docs/decisions", name+".md")); err != nil {
			t.Fatal(err)
		}
	}
	if code, stdout, stderr := runRules(t, "generate"); code != 0 {
		t.Fatalf("code %d: %s %s", code, stdout, stderr)
	}
	for _, rel := range []string{".cursor", ".kiro", ".github", "AGENTS.md"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(err) {
			t.Errorf("%s remains: %v", rel, err)
		}
	}
}
