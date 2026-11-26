# Security model and engine isolation

This document explains what `ipso` accesses, what stays offline, how each check engine is hardened against untrusted repository inputs, and where process boundaries stop.

## Network and offline guarantees

- **Strictly offline commands:** `ipso init`, `ipso check`, `ipso explain`, `ipso import`, `ipso compile`, `ipso check plan`, `ipso check ci`, `ipso check checkov`, `ipso check snyk`, `ipso check wiz`, `ipso check sonarqube`, `ipso check dependabot`, `ipso check pulumi`, `ipso check cloudformation`, `ipso check arm`, `ipso check depcruise`, `ipso check semgrep`, `ipso check archunit`, `ipso check importlinter`, `ipso check kyverno`, `ipso check gatekeeper`, `ipso check eslint`, `ipso baseline`, `ipso bundle`, `ipso render`, `ipso rules`, `ipso mcp`, `ipso hook`, and `ipso deliver <file>` (or `-`) read local files only and make no network calls.
- **`ipso premise check`:** Performs public HTTPS GET requests per ADR-0053. It sends no `Authorization` header and no cookies, rejects IP literals, private addresses, and redirects, and never modifies EDR files.
- **Control-plane and LLM commands:** Network connections occur in explicit control-plane operations (`ipso login`, `ipso status`, `ipso draft`, `ipso deliver --repo`) and in `ipso check llm` when compiled LLM checks run via a control plane (`--server` or logged-in session) or direct BYOLLM (`--llm-url` and `--llm-model`, which enforces redirect refusal and private-IP blocking while sending redacted inputs to the configured endpoint).
- **Report redaction:** Verdict reports carry input/build hashes and verdict counts; resource addresses, file paths, job names, finding IDs, and violation messages stay on the terminal.

## Engine hardening

`ipso` validates EDR structure against the embedded schema and never executes decision prose as code. Every engine runner re-verifies compiled artifacts before execution, refuses symlinks under checked trees, and strips engine-specific override variables.

**Important:** None of the external engine invocations below is an operating-system sandbox. The external tool inherits any remaining runner environment variables, so always run check and render steps without unrelated secrets in the environment.

| Engine | Hardening controls |
| --- | --- |
| dependency-cruiser | JSON rules only (validated, never executed at compile time). Rejects code-loading, cache, symlink, and grandfathering options. |
| ArchUnit | JSON rules generate a JUnit test embedding only package patterns. `ipso check archunit` regenerates the test from the verified artifact (refusing mismatches), verifies SHA-256 checksums of all three pinned jars, copies only `.class` files, strips `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVAC_OPTIONS`, and `CLASSPATH`, and runs in a temporary directory. |
| import-linter | INI config rejects `contract_types` and dotted root packages. `ipso check importlinter` recovers contracts from the verified artifact (never reading the repo's `.importlinter`), copies only `*.py` files with no symlinks, and runs `python -I` with a custom finder that parses repository code without importing or executing it. |
| Kyverno | Compile parses CEL and rejects network/cluster context variables. `ipso check kyverno` re-compiles `kyverno.yaml` byte-for-byte, copies only `.yaml`/`.yml` files with no symlinks, strips `KYVERNO_*`, and runs in a temp directory with no cluster, no registry, and no exception flags. |
| Gatekeeper (`gator`) | Compile type-checks Rego and rejects `data.inventory` and `http.send`. `ipso check gatekeeper` re-compiles byte-for-byte, copies only `.yaml`/`.yml` files with no symlinks, rejects Gatekeeper objects, list wrappers, or ambiguous YAML, and runs `gator` in a temp directory with no image and no network. |
| ESLint | Compile rejects `__proto__` and disables inline comments (`noInlineConfig`). `ipso check eslint` re-compiles the verified config byte-for-byte, passes an empty `{}` suppressions file, requires pinned `eslint`, `typescript-eslint`, and `typescript` in a `node_modules` directory outside the repository, and strips `ESLINT_*` and `TIMING`. |
| Helm and Kustomize (`ipso render`) | Runs pinned `helm` or `kustomize` in a temp directory with an empty `PATH`, temp home, no kubeconfig, and proxy variables pointing at a closed port. Refuses external bases/components/generators/transformers/validators, symlinks, remote values files, post-renderers, and plugins. Writes rendered manifests at mode `0600` in a mode `0700` directory with `.gitignore` `*`, and never prints them. |

## AI agent surfaces

- **`ipso rules generate`:** Writes only bounded `## Decision` sections, omits titles and text of records tagged `sensitive`, preserves hand-written text outside its markers, refuses symlinks, and makes no network calls. Rules files are advisory only.
- **`ipso mcp`:** Runs locally over stdio with no network calls and no authentication (reachable only by its parent process). Its sole write tool, `decisions.propose`, creates one new file with `status: proposed` that is never in force until approved by a person. `checks.evaluate` evaluates unified diffs or plans locally against compiled checks using local engines (with no outbound network calls from `ipso mcp` itself; plans pass through a private temporary file that is deleted afterwards).
- **`ipso hook`:** Runs locally with no LLM and no network calls. Never answers `allow`, so your own permission rules stay active. Any edit to `.ipso` or a decision record (and any check that cannot run) asks a person. Shell-command matching is plain text, so hooks are a guardrail for cooperating agents rather than a sandbox; keep CI as the merge gate.

## Trusted installation and vulnerability reporting

- Prefer verified [GitHub Releases](https://github.com/ipsofacto-io/ipso/releases) or Homebrew over building unreviewed forks, and verify release checksums, cosign signatures, and attestations.
- Report security issues privately through [GitHub private vulnerability reporting](https://github.com/ipsofacto-io/ipso/security/advisories/new). Do not open public issues for security vulnerabilities. See the [security policy](https://github.com/ipsofacto-io/.github/blob/main/SECURITY.md).
