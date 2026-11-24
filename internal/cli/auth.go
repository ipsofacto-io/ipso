package cli

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/auth"
)

const (
	loginUsage  = "usage: ipso login [--server <url>] [--no-browser]"
	logoutUsage = "usage: ipso logout [--server <url>]"
)

func loginCmd(args []string, stdout, stderr io.Writer, d deps) int {
	var serverFlag string
	noBrowser := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if serverFlag != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, loginUsage)
				return 2
			}
			i++
			serverFlag = args[i]
		case "--no-browser":
			noBrowser = true
		default:
			fprintln(stderr, loginUsage)
			return 2
		}
	}
	if serverFlag == "" {
		serverFlag = strings.TrimSpace(getenv(auth.EnvServerURL))
	}
	if serverFlag == "" {
		fprintln(stderr, loginUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var opener func(string) error
	if !noBrowser {
		opener = d.openBrowser
		if opener == nil {
			opener = auth.OpenSystemBrowser
		}
	}
	tok, err := auth.Login(ctx, auth.LoginOptions{
		ServerURL:   serverFlag,
		Store:       d.authStore,
		HTTPClient:  d.httpClient,
		OpenBrowser: opener,
		OnAuthURL: func(authURL string) {
			fprintf(stderr, "Open this URL to sign in:\n  %s\n", authURL)
		},
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	normalized, _ := auth.NormalizeServerURL(serverFlag)
	fprintf(stdout, "logged in to %s (expires %s)\n", normalized, tok.ExpiresAt.UTC().Format(time.RFC3339))
	return 0
}

func logoutCmd(args []string, stdout, stderr io.Writer, d deps) int {
	var serverFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if serverFlag != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fprintln(stderr, logoutUsage)
				return 2
			}
			i++
			serverFlag = args[i]
		default:
			fprintln(stderr, logoutUsage)
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := auth.Logout(ctx, d.authStore, d.httpClient, serverFlag); err != nil {
		fprintln(stderr, err)
		return 1
	}
	fprintln(stdout, "logged out")
	return 0
}
