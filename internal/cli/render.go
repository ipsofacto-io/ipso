package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
	"github.com/ipsofacto-io/ipso/internal/render"
)

const (
	renderHelmUsage      = "usage: ipso render helm <chart-dir> --out <dir> [--values file]... [--release name] [--namespace name] [--kube-version version]"
	renderKustomizeUsage = "usage: ipso render kustomize <dir> --out <dir>"
	renderUsage          = renderHelmUsage + "\n" + renderKustomizeUsage
)

func renderCmd(root string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fprintln(stderr, renderUsage)
		return 2
	}
	switch args[0] {
	case "helm":
		return renderHelm(root, args[1:], stdout, stderr)
	case "kustomize":
		return renderKustomize(root, args[1:], stdout, stderr)
	default:
		fprintln(stderr, renderUsage)
		return 2
	}
}

func renderHelm(root string, args []string, stdout, stderr io.Writer) int {
	opts, err := parseRenderArgs(args, renderHelmUsage, true)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	result, err := render.Helm(context.Background(), root, opts)
	return renderResult(result, err, stdout, stderr)
}

func renderKustomize(root string, args []string, stdout, stderr io.Writer) int {
	opts, err := parseRenderArgs(args, renderKustomizeUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	result, err := render.Kustomize(context.Background(), root, opts.Chart, opts.Out)
	return renderResult(result, err, stdout, stderr)
}

func renderResult(result render.Result, err error, stdout, stderr io.Writer) int {
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	noun := "documents"
	if result.Documents == 1 {
		noun = "document"
	}
	fprintf(stdout, "wrote %s: %d %s\n", result.Path, result.Documents, noun)
	return 0
}

// parseRenderArgs reads one source directory and the options of a render. helm is false for
// Kustomize, which takes only --out.
func parseRenderArgs(args []string, usage string, helm bool) (render.HelmOptions, error) {
	var opts render.HelmOptions
	bad := fmt.Errorf("%s", usage)
	for i := 0; i < len(args); i++ {
		flag := args[i]
		switch flag {
		case "--out", "--values", "--release", "--namespace", "--kube-version":
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return render.HelmOptions{}, bad
			}
			if flag != "--out" && !helm {
				return render.HelmOptions{}, bad
			}
			i++
			value := args[i]
			switch flag {
			case "--out":
				cleaned, err := toolrun.NormalizePath(value)
				if err != nil || cleaned == "." || opts.Out != "" {
					return render.HelmOptions{}, bad
				}
				opts.Out = cleaned
			case "--values":
				cleaned, err := toolrun.NormalizePath(value)
				if err != nil {
					return render.HelmOptions{}, bad
				}
				opts.Values = append(opts.Values, cleaned)
			case "--release":
				if opts.Release != "" {
					return render.HelmOptions{}, bad
				}
				opts.Release = value
			case "--namespace":
				if opts.Namespace != "" {
					return render.HelmOptions{}, bad
				}
				opts.Namespace = value
			case "--kube-version":
				if opts.KubeVersion != "" {
					return render.HelmOptions{}, bad
				}
				opts.KubeVersion = value
			}
		default:
			cleaned, err := toolrun.NormalizePath(flag)
			if err != nil || cleaned == "." || opts.Chart != "" {
				return render.HelmOptions{}, bad
			}
			opts.Chart = cleaned
		}
	}
	if opts.Chart == "" || opts.Out == "" {
		return render.HelmOptions{}, bad
	}
	if err := opts.Validate(); err != nil {
		return render.HelmOptions{}, bad
	}
	return opts, nil
}
