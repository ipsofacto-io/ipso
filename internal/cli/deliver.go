package cli

import (
	"io"
	"os"
	"time"

	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/delivery"
)

const deliverUsage = "usage: ipso deliver <accepted-checks.json|->"

// deliverCmd brings the accepted agent-edit checks of a control plane into this repository (ADR-0120). It
// reads the answer of GET /v1/accepted-checks from a file or from stdin and opens no connection. Any
// problem stops it before it writes anything.
func deliverCmd(root string, args []string, stdin io.Reader, stdout, stderr io.Writer, d deps) int {
	if len(args) != 1 || args[0] == "" {
		fprintln(stderr, deliverUsage)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	reader := stdin
	if args[0] != "-" {
		file, err := os.Open(args[0])
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	answer, err := delivery.Decode(reader)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	results, problems, err := delivery.Deliver(root, cfg, answer, d.now())
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(problems) > 0 {
		for _, problem := range problems {
			fprintln(stderr, problem)
		}
		fprintln(stderr, "nothing was delivered")
		return 1
	}
	if len(results) == 0 {
		fprintln(stdout, "no accepted checks to deliver")
	}
	for _, result := range results {
		switch result.Status {
		case delivery.Added:
			fprintf(stdout, "%s: added check %s (%s)\n", result.File, result.Item.ID, result.Rego)
		case delivery.Present:
			fprintf(stdout, "%s: check %s is already delivered\n", result.File, result.Item.ID)
		case delivery.Held:
			fprintf(stderr, "check %s: held, %s\n", result.Item.ID, result.Detail)
		default:
			fprintf(stderr, "check %s: skipped, %s\n", result.Item.ID, result.Detail)
		}
	}
	return 0
}
