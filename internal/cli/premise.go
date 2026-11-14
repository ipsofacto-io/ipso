package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/premise"
)

const premiseUsage = "usage: ipso premise check [--report file]"

func premiseCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 || args[0] != "check" {
		fprintln(stderr, premiseUsage)
		return 2
	}
	return premiseCheckCmd(root, args[1:], stdout, stderr, d)
}

func premiseCheckCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	reportPath, err := parsePremiseArgs(args)
	if err != nil {
		fprintln(stderr, premiseUsage)
		return 2
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	files, err := edr.Match(root, cfg.Decisions)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(files) == 0 {
		fprintln(stdout, "no EDR files found")
		if reportPath != "" {
			return writePremiseReport(reportPath, d.now(), nil, stderr)
		}
		return 0
	}
	type loaded struct {
		shown string
		rec   edr.Record
	}
	var docs []loaded
	failed := false
	for _, path := range files {
		shown := displayPath(root, path)
		doc, err := edr.ReadFile(path)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		problems := edr.Validate(doc)
		if len(problems) > 0 {
			failed = true
			for _, problem := range problems {
				fprintf(stdout, "%s: %s\n", shown, problem)
			}
			continue
		}
		rec, err := edr.RecordFrom(doc)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		docs = append(docs, loaded{shown: shown, rec: rec})
	}
	if failed {
		return 1
	}
	now := d.now()
	seen := map[string]string{}
	for _, item := range docs {
		if !item.rec.InForce(now) {
			continue
		}
		if prev, ok := seen[item.rec.ID]; ok {
			fprintf(stdout, "%s: duplicate-id: %s\n", item.shown, prev)
			return 1
		}
		seen[item.rec.ID] = item.shown
	}
	var lines []string
	rows := []premiseRow{}
	errored := false
	ctx := context.Background()
	for _, item := range docs {
		if !item.rec.InForce(now) {
			lines = append(lines, fmt.Sprintf("%s: skipped, not in force", item.shown))
			continue
		}
		for _, itemPremise := range item.rec.Premises {
			result := d.probeClient.Check(ctx, premiseSpec(itemPremise))
			lines = append(lines, premiseLine(item.shown, itemPremise.ID, result))
			rows = append(rows, premiseRowFrom(item.shown, item.rec.ID, itemPremise.ID, result))
			if result.Result == premise.ResultError {
				errored = true
			}
		}
	}
	for _, line := range lines {
		fprintln(stdout, line)
	}
	if reportPath != "" {
		if code := writePremiseReport(reportPath, now, rows, stderr); code != 0 {
			return code
		}
	}
	if errored {
		return 1
	}
	return 0
}

func parsePremiseArgs(args []string) (string, error) {
	report := ""
	for i := 0; i < len(args); i++ {
		if args[i] != "--report" || report != "" {
			return "", fmt.Errorf("%s", premiseUsage)
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			return "", fmt.Errorf("%s", premiseUsage)
		}
		i++
		report = args[i]
	}
	return report, nil
}

func premiseSpec(item edr.Premise) premise.Spec {
	return premise.Spec{
		URL:       item.URL,
		Pointer:   item.Pointer,
		Equals:    item.Equals,
		HasEquals: item.HasEquals,
		Semver:    item.Semver,
	}
}

func premiseLine(path, id string, result premise.Result) string {
	if result.Result == premise.ResultError {
		return fmt.Sprintf("%s: %s: error: %s", path, id, result.Reason)
	}
	return fmt.Sprintf("%s: %s: %s", path, id, result.Result)
}

// premiseReportVersion is the version of the premise report, which is not a verdict report and keeps its shape
// when the verdict report changes (ADR-0122).
const premiseReportVersion = 1

type premiseReport struct {
	ReportVersion int          `json:"report_version"`
	IpsoVersion   string       `json:"ipso_version"`
	EvaluatedAt   time.Time    `json:"evaluated_at"`
	Premises      []premiseRow `json:"premises"`
}

type premiseRow struct {
	Path       string          `json:"path"`
	DecisionID string          `json:"decision_id"`
	ID         string          `json:"id"`
	Result     string          `json:"result"`
	Expected   any             `json:"expected"`
	Observed   json.RawMessage `json:"observed,omitempty"`
	BodySHA256 string          `json:"body_sha256,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func premiseRowFrom(path, decisionID, id string, result premise.Result) premiseRow {
	row := premiseRow{
		Path:       path,
		DecisionID: decisionID,
		ID:         id,
		Result:     result.Result,
		Expected:   result.Expected,
		BodySHA256: result.BodySHA256,
		Error:      result.Reason,
	}
	if len(result.Observed) > 0 {
		row.Observed = append(json.RawMessage(nil), result.Observed...)
	}
	return row
}

func writePremiseReport(path string, now time.Time, rows []premiseRow, stderr io.Writer) int {
	if rows == nil {
		rows = []premiseRow{}
	}
	raw, err := json.MarshalIndent(premiseReport{
		ReportVersion: premiseReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC().Truncate(time.Second),
		Premises:      rows,
	}, "", "  ")
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	raw = append(raw, '\n')
	if err := writeReport(path, raw); err != nil {
		fprintln(stderr, err)
		return 1
	}
	return 0
}
