package cli

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/auth"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/delivery"
)

const deliverUsage = "usage: ipso deliver <accepted-checks.json|-> | --repo <owner/name> [--server url]"

// deliverCmd brings the accepted checks of a control plane into this repository (ADR-0120, ADR-0158, ADR-0160, ADR-0165).
// Given a file path or "-", it opens no network connection. Given --repo <owner/name>, it fetches
// GET /v1/accepted-checks?repo=<owner/name> using the active CLI session or IPSO_TOKEN.
func deliverCmd(root string, args []string, stdin io.Reader, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, deliverUsage)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}

	var reader io.Reader
	if strings.HasPrefix(args[0], "--") {
		var repoFlag, serverFlag string
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--repo":
				if repoFlag != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					fprintln(stderr, deliverUsage)
					return 2
				}
				i++
				repoFlag = args[i]
			case "--server":
				if serverFlag != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					fprintln(stderr, deliverUsage)
					return 2
				}
				i++
				serverFlag = args[i]
			default:
				fprintln(stderr, deliverUsage)
				return 2
			}
		}
		if repoFlag == "" {
			fprintln(stderr, deliverUsage)
			return 2
		}
		sess, err := auth.Resolve(d.authStore, serverFlag)
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		client := auth.Client{Session: sess, HTTPClient: d.httpClient}
		raw, err := client.GetRaw(context.Background(), "/v1/accepted-checks?repo="+url.QueryEscape(repoFlag))
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		reader = bytes.NewReader(raw)
	} else {
		if len(args) != 1 || args[0] == "" {
			fprintln(stderr, deliverUsage)
			return 2
		}
		reader = stdin
		if args[0] != "-" {
			file, err := os.Open(args[0])
			if err != nil {
				fprintln(stderr, err)
				return 1
			}
			defer func() { _ = file.Close() }()
			reader = file
		}
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
