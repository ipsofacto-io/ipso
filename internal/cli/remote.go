package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/auth"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const (
	statusUsage = "usage: ipso status [ref] [--query <text>] [--repo <owner/name>] [--env <name>] [--server <url>] [--json]"
	draftUsage  = "usage: ipso draft --title <title> --statement <text> [--context <text>] [--owner <team:slug>] [--repo <owner/name>] [--env <name>] [--criticality blocking|warning|advisory] [--approve] [--analyze-only] [--server <url>] [--json]"
)

func getenv(key string) string {
	return os.Getenv(key)
}

func statusCmd(args []string, stdout, stderr io.Writer, d deps) int {
	var ref, query, repo, env, serverFlag string
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--query", "-q":
			if query != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, statusUsage)
				return 2
			}
			i++
			query = args[i]
		case "--repo":
			if repo != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, statusUsage)
				return 2
			}
			i++
			repo = args[i]
		case "--env":
			if env != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, statusUsage)
				return 2
			}
			i++
			env = args[i]
		case "--server":
			if serverFlag != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, statusUsage)
				return 2
			}
			i++
			serverFlag = args[i]
		case "--json":
			asJSON = true
		default:
			if strings.HasPrefix(args[i], "-") || ref != "" {
				fprintln(stderr, statusUsage)
				return 2
			}
			ref = args[i]
		}
	}
	if ref != "" && query != "" {
		fprintln(stderr, statusUsage)
		return 2
	}
	sess, err := auth.Resolve(d.authStore, serverFlag)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	client := auth.Client{Session: sess, HTTPClient: d.httpClient}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var out mcptools.HealthOutput
	if ref != "" {
		var single mcptools.DecisionHealth
		q := url.Values{}
		if repo != "" {
			q.Set("repo", repo)
		}
		if env != "" {
			q.Set("env", env)
		}
		suffix := ""
		if len(q) > 0 {
			suffix = "?" + q.Encode()
		}
		if err := client.GetJSON(ctx, "/v1/decisions/"+url.PathEscape(ref)+"/health"+suffix, &single); err != nil {
			fprintln(stderr, err)
			return 1
		}
		out.Decisions = []mcptools.DecisionHealth{single}
	} else {
		q := url.Values{}
		if query != "" {
			q.Set("q", query)
		}
		if repo != "" {
			q.Set("repo", repo)
		}
		if env != "" {
			q.Set("env", env)
		}
		suffix := ""
		if len(q) > 0 {
			suffix = "?" + q.Encode()
		}
		if err := client.GetJSON(ctx, "/v1/decisions/health"+suffix, &out); err != nil {
			fprintln(stderr, err)
			return 1
		}
	}

	if asJSON {
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		fprintf(stdout, "%s\n", raw)
		return 0
	}
	if len(out.Decisions) == 0 {
		fprintln(stdout, "no matching decisions")
		return 0
	}
	for _, dec := range out.Decisions {
		title := dec.Title
		if dec.Sensitive || title == "" {
			title = "(sensitive)"
		}
		fprintf(stdout, "%s (%s) - %s\n", dec.Slug, dec.ID, title)
		fprintf(stdout, "  validity:   %s (status=%s", dec.Validity.State, dec.Validity.Status)
		if dec.Validity.ReviewBy != "" {
			fprintf(stdout, ", review_by=%s", dec.Validity.ReviewBy)
		}
		if dec.Validity.SupersededBy != "" {
			fprintf(stdout, ", superseded_by=%s", dec.Validity.SupersededBy)
		}
		fprintln(stdout, ")")
		for _, pr := range dec.Validity.OpenPremiseReasons {
			fprintf(stdout, "    premise %s: %s\n", pr.PremiseID, pr.ReasonCode)
		}
		fprintf(stdout, "  compliance: %s\n", dec.Compliance.State)
		for _, sc := range dec.Compliance.Scopes {
			label := sc.Repo
			if label == "" {
				label = "*"
			}
			if sc.Env != "" {
				label += " [" + sc.Env + "]"
			}
			fprintf(stdout, "    scope %s: %s", label, sc.State)
			if sc.LatestChange != nil {
				fprintf(stdout, " | change=%s (%s)", sc.LatestChange.Result, sc.LatestChange.Command)
				if sc.LatestChange.Stale {
					fprintf(stdout, " [stale>%dd]", sc.LatestChange.MaxAgeDays)
				}
				if sc.LatestChange.ModelID != "" {
					fprintf(stdout, " [AI-generated: model=%s prompt=%s]", sc.LatestChange.ModelID, sc.LatestChange.PromptVersion)
				}
			}
			if sc.LatestLive != nil {
				fprintf(stdout, " | live=%s (%s)", sc.LatestLive.Result, sc.LatestLive.Command)
				if sc.LatestLive.Stale {
					fprintf(stdout, " [stale>%dd]", sc.LatestLive.MaxAgeDays)
				}
				if sc.LatestLive.ModelID != "" {
					fprintf(stdout, " [AI-generated: model=%s prompt=%s]", sc.LatestLive.ModelID, sc.LatestLive.PromptVersion)
				}
			}
			fprintln(stdout, "")
		}
	}
	return 0
}

type humanProposalRequest struct {
	Title       string   `json:"title"`
	Statement   string   `json:"statement"`
	Context     string   `json:"context,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Criticality string   `json:"criticality,omitempty"`
	ScopeRefs   []string `json:"scope_refs"`
	ApproveNow  bool     `json:"approve_now,omitempty"`
}

type humanProposalResponse struct {
	ProposalID string `json:"proposal_id"`
	Status     string `json:"status"`
	DecisionID string `json:"decision_id,omitempty"`
	Slug       string `json:"slug,omitempty"`
}

func draftCmd(args []string, stdout, stderr io.Writer, d deps) int {
	var title, statement, contextText, owner, repo, env, criticality, serverFlag string
	approveNow := false
	analyzeOnly := false
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--title":
			if title != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			title = args[i]
		case "--statement":
			if statement != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			statement = args[i]
		case "--context":
			if contextText != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			contextText = args[i]
		case "--owner":
			if owner != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			owner = args[i]
		case "--repo":
			if repo != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			repo = args[i]
		case "--env":
			if env != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			env = args[i]
		case "--criticality":
			if criticality != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			criticality = args[i]
		case "--server":
			if serverFlag != "" || i+1 >= len(args) {
				fprintln(stderr, draftUsage)
				return 2
			}
			i++
			serverFlag = args[i]
		case "--approve":
			approveNow = true
		case "--analyze-only":
			analyzeOnly = true
		case "--json":
			asJSON = true
		default:
			fprintln(stderr, draftUsage)
			return 2
		}
	}
	if strings.TrimSpace(title) == "" || strings.TrimSpace(statement) == "" || (approveNow && analyzeOnly) {
		fprintln(stderr, draftUsage)
		return 2
	}
	if criticality == "" {
		criticality = "warning"
	}
	if criticality != "blocking" && criticality != "warning" && criticality != "advisory" {
		fprintln(stderr, draftUsage)
		return 2
	}

	sess, err := auth.Resolve(d.authStore, serverFlag)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	client := auth.Client{Session: sess, HTTPClient: d.httpClient}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var verif mcptools.VerifiabilityOutput
	if err := client.PostJSON(ctx, "/v1/verifiability", mcptools.VerifiabilityInput{
		Title:     title,
		Statement: statement,
		Context:   contextText,
		Repo:      repo,
		Env:       env,
	}, &verif); err != nil {
		fprintln(stderr, err)
		return 1
	}

	if analyzeOnly {
		if asJSON {
			raw, _ := json.MarshalIndent(verif, "", "  ")
			fprintf(stdout, "%s\n", raw)
			return 0
		}
		printVerifiability(stdout, verif)
		return 0
	}

	var scopeRefs []string
	if repo != "" {
		scopeRefs = append(scopeRefs, "repo:"+repo)
	}
	if env != "" {
		scopeRefs = append(scopeRefs, "env:"+env)
	}
	if len(scopeRefs) == 0 {
		scopeRefs = []string{"org:*"}
	}
	var created humanProposalResponse
	if err := client.PostJSON(ctx, "/v1/human-proposals", humanProposalRequest{
		Title:       title,
		Statement:   statement,
		Context:     contextText,
		Owner:       owner,
		Criticality: criticality,
		ScopeRefs:   scopeRefs,
		ApproveNow:  approveNow,
	}, &created); err != nil {
		fprintln(stderr, err)
		return 1
	}

	if asJSON {
		raw, _ := json.MarshalIndent(map[string]any{
			"verifiability": verif,
			"proposal":      created,
		}, "", "  ")
		fprintf(stdout, "%s\n", raw)
		return 0
	}
	printVerifiability(stdout, verif)
	if created.DecisionID != "" {
		fprintf(stdout, "recorded and approved decision %s (%s) via proposal %s\n", created.Slug, created.DecisionID, created.ProposalID)
	} else {
		fprintf(stdout, "created human proposal %s (status=%s)\n", created.ProposalID, created.Status)
	}
	return 0
}

func printVerifiability(stdout io.Writer, verif mcptools.VerifiabilityOutput) {
	label := ""
	if verif.AIGenerated {
		label = " [AI-generated: model=" + verif.ModelID + " prompt=" + verif.PromptVersion + "]"
	}
	fprintf(stdout, "verifiability: %s%s\n", verif.Classification, label)
	if verif.Summary != "" {
		fprintf(stdout, "  %s\n", verif.Summary)
	}
	for _, s := range verif.Suggestions {
		fprintf(stdout, "  suggestion: %s\n", s)
	}
	for _, c := range verif.CandidateChecks {
		fprintf(stdout, "  candidate check: engine=%s target=%s mode=%s\n", c.Engine, c.Target, c.Mode)
	}
}
