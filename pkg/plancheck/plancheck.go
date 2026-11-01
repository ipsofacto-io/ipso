// Package plancheck evaluates a Terraform or OpenTofu plan against a signed policy bundle, the way
// `ipso check plan --bundle` does. It is the entry point for callers outside this module that receive
// a plan rather than a checkout, such as the ipso-server HCP Terraform run task.
package plancheck

import (
	"errors"
	"io"
	"time"

	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
)

// Results a check can have. They are the words of the verdict report.
const (
	ResultPass   = "pass"
	ResultFail   = "fail"
	ResultWaived = "waived"
	ResultError  = "error"
)

// Bundle is a verified set of compiled checks, held in memory.
type Bundle struct {
	build compiler.Build
}

// Load verifies the signed OCI layout at dir against the pinned digest and the public key file.
// An unsigned layout, a bad signature, or another digest fails before anything can be evaluated.
func Load(dir, digest, publicKeyPath string) (*Bundle, error) {
	build, err := bundle.Verify(dir, digest, publicKeyPath)
	if err != nil {
		return nil, err
	}
	return &Bundle{build: build}, nil
}

// Violation is one denial. Message can quote a plan value, so a caller keeps it out of shared logs
// and out of anything it sends onward.
type Violation struct {
	Address string
	Message string
}

// Verdict is the result of one check. Count is the number of denials the result is about. Violations
// holds them for a fail, and is empty for a waiver, as the terminal output of `ipso check plan` is.
type Verdict struct {
	DecisionID string
	Slug       string
	CheckIndex int
	Mode       string
	Result     string
	Count      int
	Violations []Violation
}

// Report is the result of one evaluation.
// Blocked is true when a block-mode check has a violation that nothing covers, or when any check failed
// to evaluate. That is the rule for exit 1 of `ipso check plan`.
type Report struct {
	PlanSHA256   string
	BundleSHA256 string
	Verdicts     []Verdict
	Blocked      bool
}

// Evaluate reads one plan from r and runs every plan check in force on the calendar date of now.
// A non-empty env also limits the checks to that environment. A plan that is not a plan is an error,
// and so is anything that keeps a check from reaching a verdict.
func (b *Bundle) Evaluate(r io.Reader, env string, now time.Time) (Report, error) {
	plan, err := opa.ReadPlan(r)
	if err != nil {
		return Report{}, err
	}
	report := Report{PlanSHA256: plan.SHA256(), BundleSHA256: b.build.SHA256(), Verdicts: []Verdict{}}
	for _, entry := range b.build.Entries {
		if !entry.Selected(env, now) {
			continue
		}
		artifacts, err := b.build.Artifacts(entry)
		if err != nil {
			return Report{}, err
		}
		outcome, err := baseline.Apply(entry, baseline.Scope{Env: env}, opa.EvalCheck(entry, artifacts, plan, now))
		if err != nil {
			return Report{}, err
		}
		verdict, hard := compiler.Judge(entry, outcome)
		if hard {
			report.Blocked = true
		}
		report.Verdicts = append(report.Verdicts, publicVerdict(verdict, outcome))
	}
	return report, nil
}

// Code returns the stable code of an error from this package, or "". The code names what went wrong
// and carries no plan content, so a caller can log it where it must not log the error's text.
func Code(err error) string {
	var coded *compiler.Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}

func publicVerdict(verdict compiler.Verdict, outcome compiler.Outcome) Verdict {
	out := Verdict{
		DecisionID: verdict.DecisionID,
		Slug:       verdict.Slug,
		CheckIndex: verdict.CheckIndex,
		Mode:       verdict.Mode,
		Result:     verdict.Result,
		Count:      verdict.Violations,
	}
	if verdict.Result != ResultFail {
		return out
	}
	for _, violation := range outcome.Violations {
		if !violation.Baselined {
			out.Violations = append(out.Violations, Violation{Address: violation.Address, Message: violation.Message})
		}
	}
	return out
}
