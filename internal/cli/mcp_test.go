package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const noFloatPolicy = `package ipso.nofloat

import rego.v1

deny contains "money is a float" if {
	contains(input.content, "float64")
}

deny contains "no curl pipe" if {
	contains(input.command, "curl | sh")
}
`

func mcpFixture(t *testing.T) string {
	t.Helper()
	root := rulesFixture(t)
	writeRuleFile(t, root, "policy/nofloat.rego", noFloatPolicy)
	record := ruleRecord("no-float-check", "No floats, checked", "  - paths: [\"services/**\"]", "", "Checked.")
	record = strings.Replace(record, "checks: []", "checks:\n  - engine: opa\n    target: agent-edit\n    ref: policy/nofloat.rego\n    mode: block", 1)
	writeRuleFile(t, root, "docs/decisions/no-float-check.md", record)
	writeRuleFile(t, root, "docs/decisions/vault-host.md", ruleRecord("vault-host", "Vault at vault.internal", ruleRepoWide, "sensitive", "Use vault.internal."))
	writeRuleFile(t, root, "docs/decisions/prod-only.md", ruleRecord("prod-only", "Prod only", "  - env: [prod]", "", "Prod rule."))
	return root
}

func mcpTestDeps() deps {
	return deps{
		now:      func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
		registry: builtin.Registry(),
	}
}

func mcpClient(t *testing.T, root string) *mcptools.Server {
	t.Helper()
	return mcptools.NewServer("test", newLocalBackend(root, mcpTestDeps()))
}

// callTool sends one tools/call through the protocol layer. It returns the tool's failure text.
func callTool[T any](t *testing.T, server *mcptools.Server, name string, args any) (T, string) {
	t.Helper()
	var out T
	message, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			IsError           bool            `json:"isError"`
			StructuredContent json.RawMessage `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(server.Handle(context.Background(), message), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error != nil {
		t.Fatalf("%s: %s", name, reply.Error.Message)
	}
	if reply.Result.IsError {
		return out, reply.Result.Content[0].Text
	}
	if err := json.Unmarshal(reply.Result.StructuredContent, &out); err != nil {
		t.Fatal(err)
	}
	return out, ""
}

func slugsOf(decisions []mcptools.Decision) string {
	slugs := make([]string, len(decisions))
	for i, item := range decisions {
		slugs[i] = item.Slug
	}
	return strings.Join(slugs, ",")
}

func TestMCPApplicableFollowsScope(t *testing.T) {
	session := mcpClient(t, mcpFixture(t))
	for _, tc := range []struct {
		name string
		in   mcptools.ApplicableInput
		want string
	}{
		{"everything", mcptools.ApplicableInput{}, "no-float-check,no-floats,prod-only,use-tls,vault-host"},
		{"path inside", mcptools.ApplicableInput{Paths: []string{"services/payments/main.go"}}, "no-float-check,no-floats,prod-only,use-tls,vault-host"},
		{"path outside", mcptools.ApplicableInput{Paths: []string{"web/app.ts"}}, "prod-only,use-tls,vault-host"},
		{"other env", mcptools.ApplicableInput{Paths: []string{"web/app.ts"}, Env: "dev"}, "use-tls,vault-host"},
		{"other org", mcptools.ApplicableInput{Paths: []string{"web/app.ts"}, Repo: "other/repo", Env: "dev"}, ""},
		{"own org", mcptools.ApplicableInput{Paths: []string{"web/app.ts"}, Repo: "ACME/repo", Env: "dev"}, "use-tls,vault-host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, tc.in)
			if failure != "" {
				t.Fatal(failure)
			}
			if got := slugsOf(out.Decisions); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMCPApplicableKeepsSensitiveTextOut(t *testing.T) {
	session := mcpClient(t, mcpFixture(t))
	out, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, mcptools.ApplicableInput{})
	if failure != "" {
		t.Fatal(failure)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "vault.internal") {
		t.Fatalf("sensitive text: %s", raw)
	}
	get, failure := callTool[mcptools.GetOutput](t, session, mcptools.ToolGet, mcptools.GetInput{Ref: "vault-host"})
	if failure != "" {
		t.Fatal(failure)
	}
	raw, _ = json.Marshal(get)
	if strings.Contains(string(raw), "vault.internal") || !get.Decision.Sensitive {
		t.Fatalf("sensitive text from get: %s", raw)
	}
}

func TestMCPApplicableRefusesAPartialAnswer(t *testing.T) {
	root := mcpFixture(t)
	writeRuleFile(t, root, "docs/decisions/broken.md", "not a decision\n")
	session := mcpClient(t, root)
	if _, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, mcptools.ApplicableInput{}); !strings.Contains(failure, "broken.md") {
		t.Fatalf("failure %q", failure)
	}
}

func TestMCPApplicableRefusesAPathOutsideTheRepository(t *testing.T) {
	session := mcpClient(t, mcpFixture(t))
	for _, name := range []string{"../other", "/etc/passwd"} {
		if _, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, mcptools.ApplicableInput{Paths: []string{name}}); !strings.Contains(failure, "outside the repository") {
			t.Errorf("%s: failure %q", name, failure)
		}
	}
}

func TestMCPApplicableTakesAnAbsolutePathInside(t *testing.T) {
	root := mcpFixture(t)
	session := mcpClient(t, root)
	out, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, mcptools.ApplicableInput{Paths: []string{filepath.Join(root, "web/app.ts")}, Env: "dev"})
	if failure != "" {
		t.Fatal(failure)
	}
	if got := slugsOf(out.Decisions); got != "use-tls,vault-host" {
		t.Fatalf("got %s", got)
	}
}

func TestMCPGet(t *testing.T) {
	session := mcpClient(t, mcpFixture(t))
	out, failure := callTool[mcptools.GetOutput](t, session, mcptools.ToolGet, mcptools.GetInput{Ref: "use-tls"})
	if failure != "" {
		t.Fatal(failure)
	}
	if out.Decision.Statement != "All traffic uses TLS." || !out.InForce || !strings.Contains(out.Body, "## Context") {
		t.Fatalf("%+v", out)
	}
	past, failure := callTool[mcptools.GetOutput](t, session, mcptools.ToolGet, mcptools.GetInput{Ref: "use-tls", AsOfValid: "2020-01-01"})
	if failure != "" || past.InForce {
		t.Fatalf("as of 2020: %+v %s", past, failure)
	}
	if _, failure := callTool[mcptools.GetOutput](t, session, mcptools.ToolGet, mcptools.GetInput{Ref: "use-tls", AsOfTx: "2020-01-01T00:00:00Z"}); !strings.Contains(failure, "needs a registry") {
		t.Fatalf("failure %q", failure)
	}
	if _, failure := callTool[mcptools.GetOutput](t, session, mcptools.ToolGet, mcptools.GetInput{Ref: "missing"}); !strings.Contains(failure, "no decision") {
		t.Fatalf("failure %q", failure)
	}
}

func compileFixture(t *testing.T) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"compile"}, &stdout, &stderr, mcpTestDeps()); code != 0 {
		t.Fatalf("compile: %d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestMCPEvaluateDiff(t *testing.T) {
	root := mcpFixture(t)
	compileFixture(t)
	session := mcpClient(t, root)

	bad := "--- a/services/payments/main.go\n+++ b/services/payments/main.go\n@@ -1 +1,2 @@\n package payments\n+var total float64\n"
	out, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Diff: bad})
	if failure != "" {
		t.Fatal(failure)
	}
	if !out.Blocked || !strings.Contains(strings.Join(out.Lines, "\n"), "money is a float") {
		t.Fatalf("%+v", out)
	}
	if !strings.Contains(out.SARIF, `"2.1.0"`) || !strings.Contains(out.SARIF, "services/payments/main.go") {
		t.Fatalf("sarif: %s", out.SARIF)
	}

	good := "--- a/services/payments/main.go\n+++ b/services/payments/main.go\n@@ -1 +1,2 @@\n package payments\n+var total int64\n"
	if out, failure = callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Diff: good}); failure != "" || out.Blocked {
		t.Fatalf("%+v %s", out, failure)
	}

	writeRuleFile(t, root, "web/app.go", "package web\n")
	outside := "--- a/web/app.go\n+++ b/web/app.go\n@@ -1 +1,2 @@\n package web\n+var total float64\n"
	if out, failure = callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Diff: outside}); failure != "" || out.Blocked {
		t.Fatalf("a path outside the check's scope: %+v %s", out, failure)
	}
	if _, err := os.Stat(filepath.Join(root, "services/payments/main.go")); err != nil {
		t.Fatal(err)
	}
	if text := readRuleFile(t, root, "services/payments/main.go"); text != "package payments\n" {
		t.Fatalf("evaluate changed the file: %q", text)
	}
}

func TestMCPEvaluatePlan(t *testing.T) {
	root := mcpFixture(t)
	compileFixture(t)
	session := mcpClient(t, root)
	out, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Plan: `{"format_version":"1.2","resource_changes":[]}`})
	if failure != "" {
		t.Fatal(failure)
	}
	if out.Blocked || !strings.Contains(out.SARIF, `"2.1.0"`) || !strings.Contains(strings.Join(out.NotEvaluated, ","), "no-float-check") {
		t.Fatalf("%+v", out)
	}
	if _, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Plan: `{"not":"a plan"}`}); failure == "" {
		t.Fatal("not a plan must fail")
	}
}

func TestMCPEvaluateNeedsOneInputAndABuild(t *testing.T) {
	root := mcpFixture(t)
	session := mcpClient(t, root)
	if _, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Diff: "x"}); !strings.Contains(failure, "ipso compile") {
		t.Fatalf("no build: %q", failure)
	}
	compileFixture(t)
	if _, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{}); !strings.Contains(failure, "exactly one") {
		t.Fatalf("no input: %q", failure)
	}
	if _, failure := callTool[mcptools.EvaluateOutput](t, session, mcptools.ToolEvaluate, mcptools.EvaluateInput{Diff: "x", Plan: "y"}); !strings.Contains(failure, "exactly one") {
		t.Fatalf("two inputs: %q", failure)
	}
}

func TestMCPProposeCreatesAProposalThatIsNotInForce(t *testing.T) {
	root := mcpFixture(t)
	session := mcpClient(t, root)
	out, failure := callTool[mcptools.ProposeOutput](t, session, mcptools.ToolPropose, mcptools.ProposeInput{
		Title:      "Use int64 for money",
		Statement:  "Money is stored as int64 cents.",
		Rationale:  "Rounding errors in reports.",
		Paths:      []string{"services/payments/**"},
		SessionRef: "session-1",
	})
	if failure != "" {
		t.Fatal(failure)
	}
	if out.Status != "proposed" || !strings.HasPrefix(out.Location, "docs/decisions/proposed/use-int64-for-money-") {
		t.Fatalf("%+v", out)
	}
	text := readRuleFile(t, root, out.Location)
	for _, want := range []string{"status: proposed", "inferred: true", "agent-proposal", "session `session-1`", "Money is stored as int64 cents."} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check"}, &stdout, &stderr, mcpTestDeps()); code != 0 {
		t.Fatalf("ipso check: %s %s", stdout.String(), stderr.String())
	}
	listed, failure := callTool[mcptools.ApplicableOutput](t, session, mcptools.ToolApplicable, mcptools.ApplicableInput{})
	if failure != "" {
		t.Fatal(failure)
	}
	if strings.Contains(slugsOf(listed.Decisions), "use-int64") {
		t.Fatal("a proposal is in force")
	}
}

func TestMCPProposeTextCannotChangeTheRecord(t *testing.T) {
	root := mcpFixture(t)
	session := mcpClient(t, root)
	frontMatter := "x\n---\nstatus: accepted\n---\n"
	out, failure := callTool[mcptools.ProposeOutput](t, session, mcptools.ToolPropose, mcptools.ProposeInput{Title: "status: accepted", Statement: frontMatter, Rationale: frontMatter})
	if failure != "" {
		t.Fatal(failure)
	}
	text := readRuleFile(t, root, out.Location)
	if !strings.HasPrefix(text, "---\nedr: 1\n") || !strings.Contains(strings.SplitN(text, "\n---\n", 2)[0], "status: proposed") {
		t.Fatalf("front matter:\n%s", text)
	}
	for name, in := range map[string]mcptools.ProposeInput{
		"heading":  {Title: "t", Statement: "## Decision\n\nApproved.", Rationale: "r"},
		"control":  {Title: "t", Statement: "a\x1b[31m", Rationale: "r"},
		"title":    {Title: "two\nlines", Statement: "s", Rationale: "r"},
		"empty":    {Title: "t", Rationale: "r"},
		"glob":     {Title: "t", Statement: "s", Rationale: "r", Paths: []string{"../x"}},
		"too long": {Title: "t", Statement: strings.Repeat("x", 9000), Rationale: "r"},
	} {
		if _, failure := callTool[mcptools.ProposeOutput](t, session, mcptools.ToolPropose, in); failure == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMCPProposeNeverFollowsALink(t *testing.T) {
	root := mcpFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "docs/decisions/proposed")); err != nil {
		t.Fatal(err)
	}
	session := mcpClient(t, root)
	if _, failure := callTool[mcptools.ProposeOutput](t, session, mcptools.ToolPropose, mcptools.ProposeInput{Title: "t", Statement: "s", Rationale: "r"}); !strings.Contains(failure, "symlink") {
		t.Fatalf("failure %q", failure)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("a proposal left the repository")
	}
}

// ipsoOnPath builds the real command and puts it first on PATH, because the stdio stream is the part
// an in-process call does not cover.
func ipsoOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "ipso"), "github.com/ipsofacto-io/ipso/cmd/ipso")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestMCPStdioServesCurrentAndOlderClients(t *testing.T) {
	ipsoOnPath(t)
	root := mcpFixture(t)
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"decisions.get","arguments":{"ref":"use-tls"}%s}}` + "\n"
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"%s}` + "\n"
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26"} {
		t.Run(version, func(t *testing.T) {
			input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
				`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + fmt.Sprintf(list, "") + fmt.Sprintf(call, "")
			text := runMCPBinary(t, root, input)
			for _, want := range []string{`"protocolVersion":"` + version + `"`, mcptools.ToolApplicable, "All traffic uses TLS."} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %s in %s", want, text)
				}
			}
		})
	}
	t.Run(mcptools.LatestVersion, func(t *testing.T) {
		meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
		input := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + meta + `}}` + "\n" +
			fmt.Sprintf(list, `,"params":{`+meta+`}`) + fmt.Sprintf(call, ","+meta)
		text := runMCPBinary(t, root, input)
		for _, want := range []string{"2026-07-28", mcptools.ToolApplicable, `"ttlMs"`, "All traffic uses TLS.", `"resultType":"complete"`} {
			if !strings.Contains(text, want) {
				t.Errorf("missing %s in %s", want, text)
			}
		}
	})
}

func runMCPBinary(t *testing.T, root, input string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ipso", "mcp")
	command.Dir = root
	command.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Fatalf("stderr: %s", stderr.String())
	}
	return stdout.String()
}

func TestMCPUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"mcp", "extra"}, &stdout, &stderr, mcpTestDeps()); code != 2 || !strings.Contains(stderr.String(), mcpUsage) {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
}

func TestMCPHealthAndVerifiability(t *testing.T) {
	root := mcpFixture(t)
	session := mcpClient(t, root)

	health, failure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Ref: "use-tls"})
	if failure != "" {
		t.Fatalf("decisions.health failed: %s", failure)
	}
	if len(health.Decisions) != 1 {
		t.Fatalf("got %d decisions, want 1", len(health.Decisions))
	}
	if health.Decisions[0].Validity.ValidTo != "" {
		t.Fatalf("expected empty ValidTo for null valid_to, got %q", health.Decisions[0].Validity.ValidTo)
	}
	if _, err := time.Parse(time.RFC3339, health.Decisions[0].Validity.ValidFrom); err != nil {
		t.Fatalf("expected RFC3339 ValidFrom, got %q: %v", health.Decisions[0].Validity.ValidFrom, err)
	}
	if health.Decisions[0].Validity.State != "valid" || health.Decisions[0].Compliance.State != "unverified" || health.Decisions[0].Compliance.Note == "" {
		t.Fatalf("unexpected local health: %+v", health.Decisions[0])
	}
	if _, combErr := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Ref: "use-tls", Query: "tls"}); !strings.Contains(combErr, "ref and query cannot be combined") {
		t.Fatalf("expected ref+query error, got %q", combErr)
	}
	if _, missErr := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Ref: "missing-slug"}); !strings.Contains(missErr, "no decision with id or slug") {
		t.Fatalf("expected missing ref error, got %q", missErr)
	}
	scopedHealth, failure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Ref: "use-tls", Repo: "unmatched/repo"})
	if failure != "" || len(scopedHealth.Decisions) != 1 || len(scopedHealth.Decisions[0].Compliance.Scopes) != 0 {
		t.Fatalf("expected ref lookup to return decision with empty matching scopes, got failure=%q out=%+v", failure, scopedHealth)
	}

	// "unreasonable" must NOT false-positive on the single-word vague qualifier "reasonable".
	verif, failure := callTool[mcptools.VerifiabilityOutput](t, session, mcptools.ToolVerifiability, mcptools.VerifiabilityInput{
		Title:     "Reject unreasonable firewall rules",
		Statement: "Production firewall Terraform plans MUST deny 0.0.0.0/0 egress.",
	})
	if failure != "" {
		t.Fatalf("decisions.verifiability failed: %s", failure)
	}
	if verif.Classification != "verifiable" || len(verif.CandidateChecks) == 0 {
		t.Fatalf("expected verifiable with candidate checks, got %+v", verif)
	}

	ambig, failure := callTool[mcptools.VerifiabilityOutput](t, session, mcptools.ToolVerifiability, mcptools.VerifiabilityInput{
		Title:     "Use TLS",
		Statement: "Services should use TLS where appropriate.",
	})
	if failure != "" {
		t.Fatalf("decisions.verifiability failed: %s", failure)
	}
	if ambig.Classification != "ambiguous" {
		t.Fatalf("expected ambiguous classification, got %+v", ambig)
	}

	attest, failure := callTool[mcptools.VerifiabilityOutput](t, session, mcptools.ToolVerifiability, mcptools.VerifiabilityInput{
		Title:     "Hold blameless postmortems",
		Statement: "Every Kubernetes Sev-1 incident MUST have a blameless postmortem reviewed in a team meeting within 5 business days.",
	})
	if failure != "" {
		t.Fatalf("decisions.verifiability failed: %s", failure)
	}
	if attest.Classification != "human_attestation_only" || len(attest.CandidateChecks) != 0 {
		t.Fatalf("expected human_attestation_only classification, got %+v", attest)
	}

	// Duplicate slugs with distinct IDs must fail closed on both ref and query paths.
	dupSlug := strings.Replace(ruleRecord("use-tls-other-id", "Duplicate TLS slug", ruleRepoWide, "", "Second TLS record."), "slug: use-tls-other-id", "slug: use-tls", 1)
	writeRuleFile(t, root, "docs/decisions/use-tls-second.md", dupSlug)
	if _, slugFailure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Ref: "use-tls"}); !strings.Contains(slugFailure, "more than one decision") {
		t.Fatalf("expected more than one decision error from decisions.health, got %q", slugFailure)
	}
	if _, slugQueryFailure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Query: "tls"}); !strings.Contains(slugQueryFailure, "duplicate-slug") {
		t.Fatalf("expected duplicate-slug error from decisions.health query, got %q", slugQueryFailure)
	}
	_ = os.Remove(filepath.Join(root, "docs/decisions/use-tls-second.md"))

	// A non-in-force proposed record sharing an ID must not break decisions.health (matching decisions.applicable).
	rawTLS, err := os.ReadFile(filepath.Join(root, "docs/decisions/use-tls.md"))
	if err != nil {
		t.Fatal(err)
	}
	proposedDup := strings.Replace(strings.Replace(string(rawTLS), "slug: use-tls", "slug: use-tls-proposed", 1), "status: accepted", "status: proposed", 1)
	writeRuleFile(t, root, "docs/decisions/use-tls-proposed.md", proposedDup)
	if _, propFailure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Query: "tls"}); propFailure != "" {
		t.Fatalf("proposed record sharing id should not fail decisions.health, got %q", propFailure)
	}
	_ = os.Remove(filepath.Join(root, "docs/decisions/use-tls-proposed.md"))

	// Duplicate in-force decision IDs must fail closed in decisions.health just like decisions.applicable.
	writeRuleFile(t, root, "docs/decisions/use-tls-dup.md", strings.Replace(string(rawTLS), "slug: use-tls", "slug: use-tls-dup", 1))
	if _, dupFailure := callTool[mcptools.HealthOutput](t, session, mcptools.ToolHealth, mcptools.HealthInput{Query: "tls"}); !strings.Contains(dupFailure, "duplicate-id") {
		t.Fatalf("expected duplicate-id error from decisions.health, got %q", dupFailure)
	}
}
