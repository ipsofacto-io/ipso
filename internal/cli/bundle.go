package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const bundleUsage = `usage:
  ipso bundle pack --layout dir
  ipso bundle sign --layout dir --key private.pem
  ipso bundle verify --layout dir --digest sha256:hex --key public.pem`

func bundleCmd(root string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fprintln(stderr, bundleUsage)
		return 2
	}
	switch args[0] {
	case "pack":
		return bundlePack(root, args[1:], stdout, stderr)
	case "sign":
		return bundleSign(args[1:], stdout, stderr)
	case "verify":
		return bundleVerify(args[1:], stdout, stderr)
	default:
		fprintln(stderr, bundleUsage)
		return 2
	}
}

func bundlePack(root string, args []string, stdout, stderr io.Writer) int {
	opts, err := parseBundleArgs(args, false, false)
	if err != nil {
		fprintln(stderr, bundleUsage)
		return 2
	}
	built, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	digest, err := bundle.Pack(built, opts.layout)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	fprintf(stdout, "%s\n", digest)
	return 0
}

func bundleSign(args []string, stdout, stderr io.Writer) int {
	opts, err := parseBundleArgs(args, true, false)
	if err != nil {
		fprintln(stderr, bundleUsage)
		return 2
	}
	digest, err := bundle.Sign(opts.layout, opts.key)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	fprintf(stdout, "%s\n", digest)
	return 0
}

func bundleVerify(args []string, stdout, stderr io.Writer) int {
	opts, err := parseBundleArgs(args, true, true)
	if err != nil {
		fprintln(stderr, bundleUsage)
		return 2
	}
	if _, err := bundle.Verify(opts.layout, opts.digest, opts.key); err != nil {
		fprintln(stderr, err)
		return 1
	}
	fprintf(stdout, "%s\n", opts.digest)
	return 0
}

type bundleOptions struct {
	layout string
	key    string
	digest string
}

func parseBundleArgs(args []string, key, digest bool) (bundleOptions, error) {
	var opts bundleOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--layout":
			value, next, err := bundleFlag(args, i)
			if err != nil || opts.layout != "" {
				return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
			}
			i = next
			opts.layout = value
		case "--key":
			if !key {
				return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
			}
			value, next, err := bundleFlag(args, i)
			if err != nil || opts.key != "" {
				return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
			}
			i = next
			opts.key = value
		case "--digest":
			if !digest {
				return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
			}
			value, next, err := bundleFlag(args, i)
			if err != nil || opts.digest != "" {
				return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
			}
			i = next
			opts.digest = value
		default:
			return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
		}
	}
	if opts.layout == "" || (key && opts.key == "") || (digest && opts.digest == "") {
		return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
	}
	if digest && !bundle.ValidDigest(opts.digest) {
		return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
	}
	if strings.Contains(opts.layout, "\x00") {
		return bundleOptions{}, fmt.Errorf("%s", bundleUsage)
	}
	return opts, nil
}

func bundleFlag(args []string, i int) (string, int, error) {
	if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
		return "", 0, fmt.Errorf("%s", bundleUsage)
	}
	return args[i+1], i + 1, nil
}
