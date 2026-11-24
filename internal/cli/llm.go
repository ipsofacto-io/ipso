package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/auth"
	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/sarif"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
)

const llmUsage = "usage: ipso check llm <input|-> [--target kind] [--env name] [--input name] [--live] [--report file] [--sarif file] [--bundle dir --digest sha256:hex --key public.pem] [--server url] [--llm-url url --llm-model id]"

type llmOptions struct {
	path     string
	target   string
	env      string
	input    string
	live     bool
	report   string
	sarif    string
	bundle   string
	digest   string
	key      string
	server   string
	llmURL   string
	llmModel string
}

func parseLLMArgs(args []string) (llmOptions, error) {
	var opts llmOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			if opts.target != "" || i+1 >= len(args) || !llmcheck.ValidTarget(args[i+1]) {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.target = args[i]
		case "--env":
			if opts.env != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.env = args[i]
		case "--input":
			if opts.input != "" || i+1 >= len(args) || !baseline.ValidInput(args[i+1]) {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.input = args[i]
		case "--live":
			opts.live = true
		case "--report":
			if opts.report != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.report = args[i]
		case "--sarif":
			if opts.sarif != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.sarif = args[i]
		case "--bundle":
			if opts.bundle != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.bundle = args[i]
		case "--digest":
			if opts.digest != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.digest = args[i]
		case "--key":
			if opts.key != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.key = args[i]
		case "--server":
			if opts.server != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.server = args[i]
		case "--llm-url":
			if opts.llmURL != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.llmURL = args[i]
		case "--llm-model":
			if opts.llmModel != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return llmOptions{}, errors.New(llmUsage)
			}
			i++
			opts.llmModel = args[i]
		default:
			if strings.HasPrefix(args[i], "-") || opts.path != "" {
				return llmOptions{}, errors.New(llmUsage)
			}
			opts.path = args[i]
		}
	}
	if opts.path == "" || sameOutput(opts.report, opts.sarif) {
		return llmOptions{}, errors.New(llmUsage)
	}
	if (opts.bundle != "") != (opts.digest != "") || (opts.bundle != "") != (opts.key != "") {
		return llmOptions{}, errors.New(llmUsage)
	}
	if opts.digest != "" && !bundle.ValidDigest(opts.digest) {
		return llmOptions{}, errors.New(llmUsage)
	}
	if (opts.llmURL != "") != (opts.llmModel != "") {
		return llmOptions{}, errors.New(llmUsage)
	}
	return opts, nil
}

type serverLLMEvalRequest struct {
	DecisionID    string             `json:"decision_id"`
	Slug          string             `json:"slug"`
	Target        string             `json:"target"`
	Rubric        string             `json:"rubric"`
	Fixtures      []llmcheck.Fixture `json:"fixtures"`
	RedactedInput string             `json:"redacted_input"`
	InputSHA256   string             `json:"input_sha256"`
}

type serverLLMEvalResponse struct {
	Verdict       string             `json:"verdict"`
	Findings      []llmcheck.Finding `json:"findings"`
	ModelID       string             `json:"model_id"`
	PromptVersion string             `json:"prompt_version"`
}

func llmCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parseLLMArgs(args)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}

	var reader io.Reader = os.Stdin
	if opts.path != "-" {
		f, err := os.Open(opts.path)
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		defer func() { _ = f.Close() }()
		reader = f
	}
	rawInput, err := io.ReadAll(io.LimitReader(reader, llmcheck.DefaultMaxInputBytes+1))
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(rawInput) > llmcheck.DefaultMaxInputBytes {
		fprintf(stderr, "input exceeds %d bytes\n", llmcheck.DefaultMaxInputBytes)
		return 1
	}
	// Redact secrets locally before hashing or transmitting any excerpt (ADR-0160).
	redacted := llmcheck.Redact(string(rawInput))
	inputSHA := llmcheck.SHA256Hex([]byte(redacted))

	var build compiler.Build
	if opts.bundle != "" {
		build, err = bundle.Verify(opts.bundle, opts.digest, opts.key)
	} else {
		build, err = compiler.LoadBuild(root)
	}
	if err != nil {
		fprintln(stderr, err)
		return 1
	}

	now := d.now()
	targetLabel := opts.target
	if targetLabel == "" {
		targetLabel = "all"
	}
	report := compiler.LLMReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Target:        targetLabel,
		InputSHA256:   inputSHA,
		BuildSHA256:   build.SHA256(),
		Live:          opts.live,
		Verdicts:      []compiler.Verdict{},
	}

	var serverClient *auth.Client
	if opts.llmURL == "" {
		for _, entry := range build.Entries {
			if entry.SelectedEngineTarget("llm", opts.target, opts.env, now) {
				sess, err := auth.Resolve(d.authStore, opts.server)
				if err != nil {
					fprintln(stderr, err)
					return 1
				}
				c := auth.Client{Session: sess, HTTPClient: d.httpClient}
				serverClient = &c
				break
			}
		}
	} else {
		if _, err := auth.NormalizeServerURL(opts.llmURL); err != nil {
			fprintln(stderr, err)
			return 1
		}
	}

	type modelMeta struct {
		modelID       string
		promptVersion string
	}
	metaByKey := map[string]modelMeta{}
	scope := baseline.Scope{Env: opts.env, Input: opts.input}

	verdicts, checks, failed, selected, evalErr := evaluateChecks(d, scope, stdout, build, func(entry compiler.Entry) bool {
		return entry.SelectedEngineTarget("llm", opts.target, opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		rawSpec, ok := artifacts[llmcheck.ArtifactName]
		if !ok {
			return compiler.Outcome{Err: fmt.Errorf("missing %s in build", llmcheck.ArtifactName)}
		}
		spec, err := llmcheck.ParseAndValidate(rawSpec, entry.Target, entry.Mode == "block")
		if err != nil {
			return compiler.Outcome{Err: err}
		}
		if len(redacted) > spec.EffectiveMaxInputBytes() {
			return compiler.Outcome{Err: fmt.Errorf("redacted input (%d bytes) exceeds check max_input_bytes (%d)", len(redacted), spec.EffectiveMaxInputBytes())}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		var ans llmcheck.Answer
		var modelID, promptVer string
		if opts.llmURL != "" {
			ans, modelID, promptVer, err = evaluateBYOLLM(ctx, d.httpClient, opts.llmURL, opts.llmModel, entry.Slug, spec, redacted)
		} else {
			ans, modelID, promptVer, err = evaluateServerLLM(ctx, *serverClient, entry, spec, redacted, inputSHA)
		}
		cancel()
		if err != nil {
			return compiler.Outcome{Err: err}
		}
		key := fmt.Sprintf("%s/%d", entry.DecisionID, entry.CheckIndex)
		metaByKey[key] = modelMeta{modelID: modelID, promptVersion: promptVer}
		if ans.Verdict == "pass" {
			return compiler.Outcome{}
		}
		violations := make([]compiler.Violation, 0, len(ans.Findings))
		for _, f := range ans.Findings {
			violations = append(violations, compiler.Violation{
				Message:  fmt.Sprintf("%s (quote: %q) [AI-generated: model=%s prompt=%s]", f.Message, f.Quote, modelID, promptVer),
				Identity: []string{f.Quote},
			})
		}
		return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
	})
	if evalErr != nil {
		fprintln(stderr, evalErr)
		return 1
	}

	for i := range verdicts {
		key := fmt.Sprintf("%s/%d", verdicts[i].DecisionID, verdicts[i].CheckIndex)
		if m, ok := metaByKey[key]; ok {
			verdicts[i].ModelID = m.modelID
			verdicts[i].PromptVersion = m.promptVersion
			fprintf(stdout, "  [AI-generated] %s#%d model=%s prompt=%s\n", verdicts[i].Slug, verdicts[i].CheckIndex, m.modelID, m.promptVersion)
		}
	}
	report.Verdicts = verdicts
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("llm", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalLLMReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func evaluateServerLLM(ctx context.Context, client auth.Client, entry compiler.Entry, spec llmcheck.Spec, redactedInput, inputSHA string) (llmcheck.Answer, string, string, error) {
	var resp serverLLMEvalResponse
	err := client.PostJSON(ctx, "/v1/llm/evaluate", serverLLMEvalRequest{
		DecisionID:    entry.DecisionID,
		Slug:          entry.Slug,
		Target:        spec.Target,
		Rubric:        spec.Rubric,
		Fixtures:      spec.Fixtures,
		RedactedInput: redactedInput,
		InputSHA256:   inputSHA,
	}, &resp)
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	if strings.TrimSpace(resp.ModelID) == "" || strings.TrimSpace(resp.PromptVersion) == "" {
		return llmcheck.Answer{}, "", "", errors.New("server evaluation omitted model_id or prompt_version")
	}
	rawAns, err := json.Marshal(llmcheck.Answer{Verdict: resp.Verdict, Findings: resp.Findings})
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	// Independently verify grounded quotes locally even when evaluated via ipso-server (ADR-0158, ADR-0160).
	verified, err := llmcheck.VerifyAnswer(redactedInput, rawAns)
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	return verified, resp.ModelID, resp.PromptVersion, nil
}

func resolveBYOLLMEndpoint(normalized string) string {
	trimmed := strings.TrimRight(normalized, "/")
	switch {
	case strings.HasSuffix(trimmed, "/chat/completions"):
		return trimmed
	case strings.HasSuffix(trimmed, "/v1"):
		return trimmed + "/chat/completions"
	default:
		return trimmed + "/v1/chat/completions"
	}
}

var (
	byollmBlockedV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	byollmGlobalV6  = netip.MustParsePrefix("2000::/3")
	byollmBlockedV6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

func isPublicUnicastAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	if addr.Is4() {
		for _, p := range byollmBlockedV4 {
			if p.Contains(addr) {
				return false
			}
		}
		return true
	}
	if !byollmGlobalV6.Contains(addr) {
		return false
	}
	for _, p := range byollmBlockedV6 {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func validateBYOLLMBaseURL(raw string) (string, bool, error) {
	normalized, err := auth.NormalizeServerURL(raw)
	if err != nil {
		return "", false, err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", false, err
	}
	host := strings.ToLower(parsed.Hostname())
	allowLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if !allowLoopback {
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil && !isPublicUnicastAddr(addr) {
			return "", false, errors.New("BYOLLM endpoint must be a public unicast host or explicit loopback (localhost, 127.0.0.1, ::1)")
		}
	}
	return normalized, allowLoopback, nil
}

func byollmHTTPClient(base *http.Client, allowLoopback bool) *http.Client {
	refuse := func(*http.Request, []*http.Request) error {
		return errors.New("BYOLLM redirects are refused")
	}
	var clone http.Client
	if base != nil {
		clone = *base
	}
	if clone.Timeout == 0 {
		clone.Timeout = 60 * time.Second
	}
	clone.CheckRedirect = refuse
	if !allowLoopback && clone.Transport == nil {
		if def, ok := http.DefaultTransport.(*http.Transport); ok {
			tr := def.Clone()
			dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil || len(ips) == 0 {
					if err != nil {
						return nil, err
					}
					return nil, fmt.Errorf("no IP addresses resolved for %s", host)
				}
				var firstValid netip.Addr
				for _, ipAddr := range ips {
					addr, ok := netip.AddrFromSlice(ipAddr.IP)
					if !ok || !isPublicUnicastAddr(addr) {
						return nil, fmt.Errorf("refusing private, loopback, or metadata IP target for BYOLLM host %s", host)
					}
					if !firstValid.IsValid() {
						firstValid = addr.Unmap()
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(firstValid.String(), port))
			}
			clone.Transport = tr
		}
	}
	return &clone
}

func evaluateBYOLLM(ctx context.Context, httpClient *http.Client, baseURL, modelID, slug string, spec llmcheck.Spec, redactedInput string) (llmcheck.Answer, string, string, error) {
	normalized, allowLoopback, err := validateBYOLLMBaseURL(baseURL)
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	httpClient = byollmHTTPClient(httpClient, allowLoopback)
	payload, err := json.Marshal(map[string]any{
		"model":       modelID,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": llmcheck.SystemPrompt()},
			{"role": "user", "content": llmcheck.UserPrompt(slug, spec, redactedInput)},
		},
	})
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	endpoint := resolveBYOLLMEndpoint(normalized)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := strings.TrimSpace(getenv("IPSO_LLM_API_KEY")); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return llmcheck.Answer{}, "", "", fmt.Errorf("BYOLLM HTTP %d", resp.StatusCode)
	}
	var completion struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &completion); err != nil || len(completion.Choices) == 0 {
		return llmcheck.Answer{}, "", "", errors.New("invalid BYOLLM chat completion response")
	}
	content := stripJSONFence(completion.Choices[0].Message.Content)
	verified, err := llmcheck.VerifyAnswer(redactedInput, []byte(content))
	if err != nil {
		return llmcheck.Answer{}, "", "", err
	}
	resolvedModel := strings.TrimSpace(completion.Model)
	if resolvedModel == "" {
		resolvedModel = modelID
	}
	return verified, resolvedModel, llmcheck.PromptVersion, nil
}

func stripJSONFence(s string) string {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "```") {
		if idx := strings.IndexByte(trimmed, '\n'); idx >= 0 {
			trimmed = trimmed[idx+1:]
		}
		trimmed = strings.TrimSuffix(strings.TrimSpace(trimmed), "```")
	}
	return strings.TrimSpace(trimmed)
}
