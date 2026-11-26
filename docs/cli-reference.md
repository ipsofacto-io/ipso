# CLI reference

Complete command reference, compiler rules, pinned engine versions, and evidence formats for the `ipso` CLI.

Run all commands from the repository root. Global flags are limited to help (`-h`, `--help`, `help`) and version (`-v`, `--version`, `version`).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (no blocking violations and no runtime errors) |
| `1` | Runtime failure, validation error, blocking violation, or missing/ambiguous slug |
| `2` | Bad CLI usage |

## Command reference

| Invocation | Behavior and exit behavior |
| --- | --- |
| `ipso init` | Creates `.ipso/config.yaml` with `decisions: [docs/decisions/**/*.md]` when absent. Prints `wrote .ipso/config.yaml` or `.ipso/config.yaml already exists`. Exits `0`, `1` on I/O error, `2` on bad usage. |
| `ipso check` | Loads `.ipso/config.yaml` (or defaults) and validates every matched EDR file against the embedded schema and required headings. Does not run check engines. Prints `<path>: ok`, `<path>: <problem>`, or `no EDR files found`. Exits `0` when all files are valid or none match, `1` if any file fails. |
| `ipso explain <slug>` | Finds the EDR matching frontmatter `slug` and prints `title:`, `status:`, `id:`, `path:`, any `sources:`, and the `## Decision` body. Exits `1` when missing or ambiguous. |
| `ipso import [path...]` | Rewrites MADR or Nygard ADR Markdown files in place as EDR files with `inferred: true` for missing fields. Defaults to `docs/adr` and `docs/decisions`. Valid EDR files are skipped unchanged. |
| `ipso compile` | Compiles checks on in-force records (`accepted`, `verified`, or `needs-review` with today in `[valid_from, valid_to)`) into `.ipso/build/` with a `.gitignore` of `*`. Failures leave the previous build intact. |
| `ipso premise check [--report file]` | Probes premises on in-force decisions via public HTTPS GET and compares JSON pointers with `equals` or `semver`. Does not read `every`, edit EDR files, or call a registry. `--report` writes premise ID, result, expected/observed values, and body hash (never the response body). Exits `0` when all probes pass or fail (including zero selected); `1` on probe error, invalid record, or duplicate ID. |
| `ipso baseline create` / `update <subcommand> <args>` | Runs an engine check and records (`create`) or trims (`update`) violation fingerprints in `.ipso/baseline.json`, keyed per `--env` and `--input`. Run `ipso compile` afterwards. Refuses `ci`. Exits `0` even with violations; `1` on error or `update` with no baseline file. See [baseline.md](baseline.md). |
| `ipso baseline export <decision-id>` | Prints sorted fingerprints for one decision from `.ipso/baseline.json` as JSON (no salt) for control-plane upload. Offline, read-only. |
| `ipso bundle pack --layout dir` | Packages `.ipso/build/` into a mode `0700` OCI image layout and prints `sha256:<digest>`. |
| `ipso bundle sign --layout dir --key private.pem` | Signs the layout's image manifest with an unencrypted PKCS#8 P-256 key and refuses a second signature. |
| `ipso bundle verify --layout dir --digest sha256:hex --key public.pem` | Verifies the digest pin, signature, and artifact hashes offline. Exits `1` if unsigned, mismatched, or invalid. |
| `ipso check plan <plan.json>` (or `-`) `[--env name] [--input name] [--report file] [--sarif file] [--bundle dir --digest sha256:hex --key public.pem]` | Evaluates compiled `terraform-plan` OPA checks against `terraform show -json` or `tofu show -json`. With `--bundle`, verifies and evaluates the signed OCI layout instead of `.ipso/build/`. Exits `0` when no blocking check fails and no check errors. |
| `ipso check ci <evidence.json>` (or `-`) `--sha <sha> [--env name] [--report file] [--sarif file]` | Evaluates compiled `ci-binding` checks against a CI job evidence file for `--sha`. Fails closed if a bound job is missing or did not conclude `success`. |
| `ipso check checkov <results.json>` (or `-`) `[--env name] [--input name] [--report file] [--sarif file]` | Evaluates compiled `checkov` checks against a Checkov JSON report. Fails if a bound ID failed, was skipped, or was absent (do not pass `--quiet` to Checkov). |
| `ipso check <snyk/wiz/sonarqube/dependabot> <evidence.json>` (or `-`) `[--env name] [--input name] [--report file] [--sarif file]` | Evaluates compiled finding checks against a scanner evidence JSON file (max 1 MiB). Fails if a bound ID is open or the scan did not finish (`status: failed` is an error that waivers cannot cover). |
| `ipso check <pulumi/cloudformation/arm> <input>` (or `-`) `[--env name] [--input name] [--report file] [--sarif file]` | Evaluates compiled OPA checks for `pulumi-preview`, `cloudformation-template` (including `cdk synth`), or `arm-template` (including `bicep build`). Static file reads only. See [adapters.md](adapters.md). |
| `ipso check depcruise <path>... [--env name] [--input name] [--report file] [--sarif file]` | Runs `depcruise` from `PATH` (`^18.7.0`, 10-minute timeout per check) on verified configs. Fails if missing, out of range, erroring, or finding zero modules. |
| `ipso check semgrep <path>... [--env name] [--input name] [--report file] [--sarif file]` | Runs pinned `semgrep` (`1.182.1`, 10-minute timeout per config) from `PATH` on verified configs. Fails if missing, version-mismatched, erroring, skipping a rule, or scanning zero files. |
| `ipso check archunit <classes-dir>... --jars <dir> [--env name] [--input name] [--report file] [--sarif file]` | Compiles and runs canonical `ArchitectureTest.java` using `javac`/JDK 17+ and the three pinned jars (10-minute timeout per check). See [archunit-rules.md](archunit-rules.md). |
| `ipso check importlinter <source-dir>... [--env name] [--input name] [--report file] [--sarif file]` | Runs pinned `import-linter` (`2.15`) and `grimp` (`3.18`) via `python` from `PATH` on a copy of `*.py` files (10-minute timeout per check). Parses source without importing repository code. |
| `ipso check kyverno <path>... [--env name] [--input name] [--report file] [--sarif file]` | Runs pinned `kyverno` (`1.19.2`, 10-minute timeout per check) from `PATH` on verified policies and copied `.yaml`/`.yml` manifests. |
| `ipso check gatekeeper <path>... [--env name] [--input name] [--report file] [--sarif file]` | Runs pinned `gator` (`3.23.1` / OPA `v1.17.1`, 10-minute timeout per check) from `PATH` on verified ConstraintTemplate/Constraint files and copied manifests. |
| `ipso check eslint <path>... [--env name] [--input name] [--report file] [--sarif file]` | Runs pinned `eslint` (and pinned `typescript-eslint` + `typescript` for TypeScript checks) from `PATH` outside the repo with an empty suppressions file `{}`. See [eslint-rules.md](eslint-rules.md). |
| `ipso check llm <input>` (or `-`) `[--target kind] [--env name] [--input name] [--live] [--report file] [--sarif file] [--bundle ...] [--server url] [--llm-url url --llm-model id]` | Evaluates compiled `engine: llm` checks via a control plane (`--server` or logged-in session) or direct BYOLLM (`--llm-url` and `--llm-model`) with input redaction and verbatim quote verification. |
| `ipso render helm <chart-dir> --out <dir> [--values file]... [--release name] [--namespace name] [--kube-version version]` | Renders a Helm chart offline with pinned Helm `4.3.1` into `<dir>/manifests.yaml`. See [kubernetes.md](kubernetes.md). |
| `ipso render kustomize <dir> --out <dir>` | Renders a Kustomize directory offline with pinned Kustomize `5.8.3` into `<dir>/manifests.yaml`. Refuses external resources, symlinks, and plugins. See [kubernetes.md](kubernetes.md). |
| `ipso rules generate` / `check` | Generates or verifies agent rules files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot, Cursor, Kiro). `check` exits `1` when out of date. See [rules-files.md](rules-files.md). |
| `ipso mcp` | Serves local MCP tools over stdio for the current directory until the client disconnects. See [mcp.md](mcp.md). |
| `ipso hook <claude-code/codex/copilot/cursor/kiro> [event] [--bundle ...]` | Reads one hook event on stdin and responds in that agent's protocol format. Exits `0` on answers (including denials), except `2` for Kiro refusals or bad usage. See [hooks.md](hooks.md). |
| `ipso deliver <accepted-checks.json>` (or `-`, or `--repo <owner/name> [--server url]`) | Delivers human-approved checks from a control plane into `.ipso/checks/` and updates matching EDR frontmatter. See [deliver.md](deliver.md). |
| `ipso login [--server url] [--no-browser]` / `ipso logout [--server url]` | Authenticates or clears a CLI session via loopback PKCE for optional control-plane commands. |
| `ipso status [ref] [--query text] [--repo owner/name] [--env name] [--server url] [--json]` | Queries decision health (validity and compliance) from a control plane. |
| `ipso draft --title <t> --statement <s> [...]` | Drafts and optionally analyzes or approves a decision via a control plane. |

## Engine compiler rules

`ipso compile` evaluates only records in force today (`accepted`, `verified`, or `needs-review` with today in `[valid_from, valid_to)`). An explicit check `mode` is preserved; otherwise criticality maps `blocking` to `block`, `warning` to `warn`, and `advisory` to `advise`. Checks with no registered compiler are skipped with a notice, and `llm-advisory` is advisory-only.

The conformance suite (`ci / conformance` on PRs and pushes to `main`, `release / conformance` before tags publish) compiles OPA, Semgrep, dependency-cruiser, ArchUnit, import-linter, Kyverno, Gatekeeper, and ESLint fixtures and fails if any pinned engine disagrees with the expected verdict.

- **OPA (`engine: opa`):** `ref: ipso:<provider>/<name>` with `target: terraform-plan` compiles a built-in template ([templates.md](templates.md)) into `terraform.rego`. Any other `ref` is a repository `.rego` file compiled to `policy.rego`.
- **Gatekeeper (`engine: opa`, `target: gatekeeper`):** Reads one YAML file containing a ConstraintTemplate and Constraint (Rego v1) and writes `constraint-template.yaml` and `constraint.yaml`. Maps `block`/`warn`/`advise` to `deny`/`warn`/`dryrun`. Rejects `data.inventory`, `http.send`, and `import rego.v1`. Runs with pinned `gator` `3.23.1`.
- **Kyverno (`engine: kyverno`):** Reads one ValidatingPolicy YAML file and writes `kyverno.yaml`. Maps `block`/`warn`/`advise` to `Deny`/`Warn`/`Audit`. Rejects CEL context variables `http`, `image`, `resource`, `globalContext`, and `generator`. Runs with pinned `kyverno` `1.19.2`.
- **Semgrep (`engine: semgrep`):** Reads one YAML rule file or built-in `ipso:<language>/<name>` template ([semgrep-templates.md](semgrep-templates.md)) and writes `semgrep.yaml`. Maps `block`/`warn`/`advise` to `ERROR`/`WARNING`/`INFO`. Rejects autofix, join mode, extract mode, version gates, `interfile`, `taint_match_on`, `commutative_compop`, and unlisted matching options. Runs with pinned `semgrep` `1.182.1`.
- **dependency-cruiser (`engine: depcruise`):** Reads one JSON rule file and writes `depcruise.json`. Maps `block`/`warn`/`advise` to `error`/`warn`/`info` (`ignore` stays `ignore`). Rejects `extends`, code-loading/cache/symlink options (`webpackConfig`, `babelConfig`, `cache`, `externalModuleResolutionStrategy`, `parser`, `detectJSDocImports`, `detectImportsInAmbientModules`, `preserveSymlinks`), grandfathering options (`knownViolations`, `baseline`, `ignoreKnown`), and report-only options (`focus`, `reaches`, `highlight`, `collapse`, `affected`, `prefix`, `suffix`, `progress`, `reporterOptions`). Keeps `baseDir` and `tsConfig.fileName` inside the repository. Runs with `depcruise` `^18.7.0`.
- **ArchUnit (`engine: archunit`):** Reads one JSON rule file ([archunit-rules.md](archunit-rules.md)) and generates `ArchitectureTest.java`. Runs with JDK 17+ and ArchUnit `1.5.1` + JUnit Jupiter pinned jars.
- **import-linter (`engine: importlinter`):** Reads one `.importlinter` file and writes `importlinter.ini`. Supports the five built-in contract types in import-linter `2.15` (with `grimp` `3.18`) and rejects `contract_types`, report-only keys, and dotted root packages. Layers and independence lists require at least two entries.
- **ESLint (`engine: eslint`):** Reads one JSON rule file for `target: javascript` or `typescript` ([eslint-rules.md](eslint-rules.md)) and writes `eslint.config.mjs` with `noInlineConfig`. Maps `block` to `error` and `warn`/`advise` to `warn`. Rejects `__proto__`.
- **CI binding (`engine: ci-binding`):** Writes `binding.json` from `job`.
- **Checkov (`engine: checkov`):** Writes `binding.json` from Checkov ID in `ref` (such as `CKV_AWS_24`).
- **Security scanners (`snyk`, `wiz`, `sonarqube`, `dependabot`):** Writes `binding.json` from finding ID in `ref`.

## CI job evidence

`ipso check ci` runs offline and trusts the evidence file and `--sha`. Generate the evidence file in the same workflow job, filtering strictly to GitHub Actions check runs (`app_id=15368`) so third-party apps cannot spoof job names:

```yaml
permissions:
  checks: read
  contents: read
steps:
  - uses: actions/checkout@v4
  - name: Job evidence
    env:
      SHA: ${{ github.event.pull_request.head.sha || github.sha }}
      GH_TOKEN: ${{ github.token }}
    run: |
      gh api --method GET -H "Accept: application/vnd.github+json" \
        "repos/${{ github.repository }}/commits/${SHA}/check-runs?filter=latest&app_id=15368&per_page=100" \
        --jq '{evidence_version:1, sha:env.SHA, jobs:[.check_runs[] | {name:.name, conclusion:.conclusion}]}' \
        > evidence.json
      ipso check ci evidence.json --sha "$SHA"
```

- Unfinished jobs have `conclusion: null` and fail closed.
- Missing jobs fail closed.
- The snippet reads up to 100 check runs; repositories with more must paginate.

## Security tool evidence

`ipso check snyk`, `ipso check wiz`, `ipso check sonarqube`, and `ipso check dependabot` read a local JSON evidence file (at most 1 MiB) generated in the same CI job from your scanner's output. Never pass an evidence file committed in a pull request.

```json
{"evidence_version": 1, "tool": "snyk", "status": "success", "findings": [{"id": "SNYK-JS-LODASH-590103"}]}
```

Schema rules:

- Unknown keys are rejected; `tool` must match the subcommand; `status` must be `success` or `failed`.
- `findings` is an array of objects containing only `id` (severity is not a field).
- On `status: success`, each matching open ID fails once per object, and absent IDs pass.
- On `status: failed`, every selected check errors (waivers do not cover incomplete scans).
- Verdict reports and SARIF files store only the evidence hash and verdict counts; finding IDs stay on the terminal.

Recommended ID mappings from vendor outputs:

| Tool | Source field to map into `findings[].id` |
| --- | --- |
| Snyk Open Source | `vulnerabilities[].id` from `snyk test --json` |
| Snyk Code | SARIF `ruleId` |
| SonarQube | Issue rule key |
| Dependabot | GHSA ID of open alerts |
| Wiz | Rule or control ID named by the decision |
