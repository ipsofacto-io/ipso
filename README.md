# ipso

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15758/badge)](https://www.bestpractices.dev/en/projects/15758)

CLI, check compilers, AI agent hooks, and local MCP server that turn **Engineering Decision Records (EDRs)** into deterministic, enforced checks.

`ipso` is the Apache-2.0 adoption surface for the ipso ecosystem. It validates EDR files offline against the embedded EDR 1.1.0 schema, compiles in-force decisions into checks for policy and static analysis engines you already run, and enforces them in CI, on infrastructure plans, and before AI coding agents edit code.

## Install

Choose one option:

```bash
# Go toolchain
go install github.com/ipsofacto-io/ipso/cmd/ipso@latest
```

```bash
# Homebrew (once the tap release secret is enabled)
brew install ipsofacto-io/tap/ipso
```

You can also download prebuilt binaries from [GitHub Releases](https://github.com/ipsofacto-io/ipso/releases). Every release ships `checksums.txt`, keyless cosign signatures, a CycloneDX SBOM, and GitHub artifact attestations. (The container image `ghcr.io/ipsofacto-io/ipso` is currently private.)

## Quick start

From the root of a repository that stores Engineering Decision Records:

```bash
ipso init            # creates .ipso/config.yaml
ipso check           # validates all EDR files against the schema
ipso compile         # compiles in-force checks into .ipso/build/
ipso explain <slug>  # prints a decision's metadata and Decision section
```

`ipso init` creates `.ipso/config.yaml` with the default glob (used automatically if the config file is absent):

```yaml
decisions:
  - docs/decisions/**/*.md
```

Place your EDR Markdown files under `docs/decisions/`, then run `ipso check` and `ipso compile`.

## Supported check engines

`ipso compile` compiles in-force decisions (`accepted`, `verified`, or `needs-review` within `[valid_from, valid_to)`) into `.ipso/build/`. Every engine check accepts `--sarif <file>` for GitHub Code Scanning ([docs/sarif.md](docs/sarif.md)) and `--report <file>` for structured verdict evidence.

| Engine / target | Input rule format | CLI command | Documentation |
| --- | --- | --- | --- |
| OPA (`terraform-plan`) | Repository `.rego` or built-in `ipso:<provider>/<name>` template | `ipso check plan <plan.json\|->` | [docs/templates.md](docs/templates.md) |
| OPA (`pulumi-preview`, `cloudformation-template`, `arm-template`) | Repository `.rego` | `ipso check pulumi`, `cloudformation`, `arm` | [docs/adapters.md](docs/adapters.md) |
| OPA (`gatekeeper`) | ConstraintTemplate + Constraint YAML | `ipso check gatekeeper <path>...` | [docs/kubernetes.md](docs/kubernetes.md) |
| Kyverno | ValidatingPolicy YAML | `ipso check kyverno <path>...` | [docs/kubernetes.md](docs/kubernetes.md) |
| Semgrep | Repository YAML or built-in `ipso:<lang>/<name>` template | `ipso check semgrep <path>...` | [docs/semgrep-templates.md](docs/semgrep-templates.md) |
| dependency-cruiser | JSON rule file | `ipso check depcruise <path>...` | [docs/cli-reference.md](docs/cli-reference.md#engine-compiler-rules) |
| ArchUnit | JSON rule file | `ipso check archunit <classes-dir>... --jars <dir>` | [docs/archunit-rules.md](docs/archunit-rules.md) |
| import-linter | `.importlinter` INI file | `ipso check importlinter <source-dir>...` | [docs/cli-reference.md](docs/cli-reference.md#engine-compiler-rules) |
| ESLint | JSON rule file (`javascript` or `typescript`) | `ipso check eslint <path>...` | [docs/eslint-rules.md](docs/eslint-rules.md) |
| CI job binding | Existing CI job name (`engine: ci-binding`) | `ipso check ci <evidence.json\|-> --sha <sha>` | [docs/cli-reference.md](docs/cli-reference.md#ci-job-evidence) |
| Checkov | Checkov check ID (`ref: CKV_*`) | `ipso check checkov <results.json\|->` | [docs/cli-reference.md](docs/cli-reference.md#engine-compiler-rules) |
| Security scanners (`snyk`, `wiz`, `sonarqube`, `dependabot`) | Scanner finding ID in `ref` | `ipso check <tool> <evidence.json\|->` | [docs/cli-reference.md](docs/cli-reference.md#security-tool-evidence) |
| LLM (`engine: llm`) | `.llm.json` check specification | `ipso check llm <input\|->` | [docs/deliver.md](docs/deliver.md) |

## Commands

Run all commands from the repository root. See [docs/cli-reference.md](docs/cli-reference.md) for complete flags, compiler validation rules, pinned tool versions, evidence schemas, and output formats.

### Authoring and validation

| Command | Purpose |
| --- | --- |
| `ipso init` | Create `.ipso/config.yaml` with the default decisions glob |
| `ipso check` | Validate all matched EDR files against the embedded EDR schema and required headings |
| `ipso explain <slug>` | Display metadata, sources, and the `## Decision` section for one EDR |
| `ipso import [path...]` | Convert MADR or Nygard ADRs under `docs/adr` and `docs/decisions` into inferred EDR files |
| `ipso premise check [--report file]` | Probe premises on in-force decisions via public HTTPS GET without editing EDR files |

### Compiling and evaluating checks

| Command | Purpose |
| --- | --- |
| `ipso compile` | Compile in-force checks into `.ipso/build/` |
| `ipso check plan <plan.json\|->` | Evaluate compiled OPA checks against `terraform show -json` or `tofu show -json` (or a signed bundle via `--bundle`) |
| `ipso check <engine> ...` | Run compiled checks for `ci`, `checkov`, `snyk`, `wiz`, `sonarqube`, `dependabot`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, `eslint`, or `llm` |
| `ipso render helm\|kustomize` | Render Helm charts or Kustomize overlays offline into plain manifests for `kyverno` and `gatekeeper` checks |

### Baselines and signed bundles

| Command | Purpose |
| --- | --- |
| `ipso baseline create\|update <subcommand> <args>` | Record or trim existing violation fingerprints in `.ipso/baseline.json` so legacy findings are waived ([docs/baseline.md](docs/baseline.md)) |
| `ipso baseline export <decision-id>` | Print sorted fingerprints for one decision as JSON for control-plane upload |
| `ipso bundle pack\|sign\|verify` | Package `.ipso/build/` as an OCI layout, sign with PKCS#8 P-256, and verify offline |

### AI coding agents and control plane

| Command | Purpose |
| --- | --- |
| `ipso rules generate\|check` | Sync in-force decisions into `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot, Cursor, and Kiro rules files ([docs/rules-files.md](docs/rules-files.md)) |
| `ipso mcp` | Serve local decisions and evaluation tools over stdio MCP ([docs/mcp.md](docs/mcp.md)) |
| `ipso hook <agent> [event]` | Evaluate `agent-edit` checks for Claude Code, Codex, Copilot, Cursor, and Kiro hooks ([docs/hooks.md](docs/hooks.md)) |
| `ipso login` / `ipso logout` | Authenticate via loopback PKCE for optional control-plane commands |
| `ipso status` / `ipso draft` | Query decision health or draft decisions against a control plane |
| `ipso deliver <file\|-> \| --repo <owner/name>` | Deliver accepted checks from a control plane into the repository ([docs/deliver.md](docs/deliver.md)) |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (no blocking violations and no runtime errors) |
| `1` | Runtime failure, validation error, blocking violation, or missing/ambiguous slug |
| `2` | Invalid command or flag usage |

## CI/CD and platform integrations

| Integration | Location / guide |
| --- | --- |
| GitHub Actions | [`ipsofacto-io/ipso-action`](https://github.com/ipsofacto-io/ipso-action) and [docs/github-action.md](docs/github-action.md) |
| GitLab CI/CD Catalog component | [`packaging/gitlab`](packaging/gitlab) and [docs/gitlab.md](docs/gitlab.md) |
| Azure Pipelines task | [`packaging/azure-pipelines`](packaging/azure-pipelines) and [docs/azure-pipelines.md](docs/azure-pipelines.md) |
| Atlantis | [docs/atlantis.md](docs/atlantis.md) |
| Spacelift, env0, and Scalr | [docs/platforms.md](docs/platforms.md) |
| Backstage plugin | [`packaging/backstage`](packaging/backstage) |
| AI coding agents (Claude Code, Codex, Copilot, Cursor, Kiro) | [`ipsofacto-io/agent-plugins`](https://github.com/ipsofacto-io/agent-plugins), [docs/hooks.md](docs/hooks.md), [docs/mcp.md](docs/mcp.md) |

## Security model

- **Offline by default:** Validation, compilation, plan/code/manifest checks, baselines, bundles, `ipso rules`, `ipso mcp`, and `ipso hook` make no network calls. Only `ipso premise check` (public HTTPS GET, no credentials, no redirects, no private IPs) and explicit control-plane commands (`ipso login`, `ipso status`, `ipso draft`, `ipso deliver --repo`, server-mediated `ipso check llm`) touch the network.
- **No untrusted repo code execution:** Compilers reject code-loading options, inline suppressions, symlinks, and network/cluster context hooks, and check runners re-verify compiled artifacts before invoking pinned external engines.
- **Keep runner secrets out of engine steps:** External engines (JVM, Python, Node, Helm, Kustomize, Kyverno, gator) inherit non-stripped runner environment variables and are not an OS sandbox. Run check steps without unrelated secrets.
- **Report vulnerabilities privately:** Use [GitHub private vulnerability reporting](https://github.com/ipsofacto-io/ipso/security/advisories/new) rather than opening a public issue. See [SECURITY.md](https://github.com/ipsofacto-io/.github/blob/main/SECURITY.md).

Read [docs/security.md](docs/security.md) for the complete per-engine isolation and hardening rules.

## Documentation

- [CLI reference and compiler rules](docs/cli-reference.md)
- [Security and engine isolation details](docs/security.md)
- [Built-in Terraform OPA templates](docs/templates.md) and [Semgrep templates](docs/semgrep-templates.md)
- [IaC adapters (Pulumi, CloudFormation, CDK, Bicep)](docs/adapters.md)
- [Kubernetes rendering and checks (Helm, Kustomize, Kyverno, Gatekeeper)](docs/kubernetes.md)
- [ArchUnit rules](docs/archunit-rules.md) and [ESLint rules](docs/eslint-rules.md)
- [SARIF output](docs/sarif.md), [Baselines](docs/baseline.md), and [Delivering accepted checks](docs/deliver.md)
- [AI agent hooks](docs/hooks.md), [Local MCP server](docs/mcp.md), and [Agent rules files](docs/rules-files.md)

## Public Go packages

This module never depends on `ipso-server`. Public packages under `pkg/` keep CLI and control-plane evaluation aligned while everything else stays under `internal/`:

- `pkg/edrcheck` and `pkg/edrrender`: validate and render EDR files using the embedded EDR 1.1.0 schema.
- `pkg/plancheck`: evaluate a Terraform/OpenTofu plan against a signed policy bundle.
- `pkg/rulecheck`: vet and evaluate `agent-edit` Rego rules.
- `pkg/llmcheck`: vet `.llm.json` specs, redact inputs, and verify verbatim quotes for `engine: llm` checks.
- `pkg/premisecheck`: probe premise URLs with the shared client and network policy.
- `pkg/mcptools`: shared MCP tool contract (`decisions.applicable`, `decisions.get`, `decisions.health`, `decisions.verifiability`, `checks.evaluate`, `decisions.propose`).

## Releases

Pushes to `main` open a `release-please` pull request; merging it tags `vX.Y.Z` and triggers the pinned SLSA Build Level 3 release workflow in `ipsofacto-io/.github` (from v0.1.1 onward). Each release publishes binaries, `checksums.txt`, a CycloneDX SBOM, keyless cosign signatures, and GitHub artifact attestations.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).

Copyright 2026 Luca Bertelli.

## Contributing

Follow the contributor guidelines in [ipsofacto-io/.github](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md). All commits require a `Signed-off-by` trailer (`git commit -s`).
