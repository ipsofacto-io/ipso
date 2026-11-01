# SARIF output

Every engine check takes `--sarif <file>`: `plan`, `ci`, `checkov`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, and `eslint`. The file holds one SARIF 2.1.0 run. The contract is ADR-0058 in `ipsofacto-io/ipso-spec`, and ADR-0059 adds the input names to the category.

```bash
ipso compile
ipso check semgrep . --sarif semgrep.sarif
```

Run ipso from the repository root. File locations are relative to the working directory, and GitHub resolves them from the root of the checkout, so a run from a subdirectory points alerts at files that do not exist.

The file is written with the same rules as `--report`: mode 0600, a symlink at the destination or its parent is refused, and the destination is replaced by rename. `--report` and `--sarif` cannot name the same file. `--sarif` does not change the exit code.

## What a run contains

| Verdict | Result |
| --- | --- |
| `pass` | None |
| `fail` | Level from the mode: block is `error`, warn is `warning`, advise is `note` |
| `waived` | The same result at `note` level, with a message that starts with `Waived:` and an `external` suppression |
| `error` | An `error` result on the decision file with the reason code only |

Semgrep and ESLint emit one result per finding, at its file and line. Every other engine emits one result per failed check, on the decision file, with the violation count. A violation a baseline covers (see [baseline.md](baseline.md)) is marked like a waived one, at `note` level, with a `Baselined:` message and an `external` suppression. Every result links to its decision file through `relatedLocations`, and rule help names the file and the `ipso explain <slug>` command.

GitHub ignores the suppression, so a waived result stays an open alert at note severity until the waiver ends or the finding is fixed.

A run holds at most 5,000 results. When more exist, the most severe are kept and a tool notification states how many were omitted.

## What a run leaves out

Messages are written by ipso. Engine messages, plan values, resource addresses, rule ids of the engine, waiver approvers, and error text stay on the terminal. Semgrep and ESLint source paths and lines are included because they name files the repository's readers can already see.

## Uploading

Each run has its own category, so upload one file per run. The category is `ipso/<subcommand>/`, followed by the `--env` and `--input` values when a run has them: `ipso/plan/prod/`, `ipso/plan/-/stack-a/`, or `ipso/plan/prod/stack-a/`. An upload replaces the alerts of its category for that ref:

- A run with no selected checks is valid and empty, so it closes the alerts of that category.
- Renaming an env or input starts a new category, so the old category's alerts stay until they are closed.
- An errored Semgrep or ESLint check has one result on the decision file and no per-finding results, so its per-finding alerts close until the next successful run. The command exits 1 in that case.

GitHub labels alerts on decision files as documentation, because they sit in Markdown files. Its "Only alerts in application code" filter hides them, so turn that filter off to see every ipso result.

## Older builds

`ipso compile` records each decision's path and title in the manifest. `--sarif` refuses a build or bundle without them with `build-manifest`, and without `--sarif` such a build evaluates as before. A decision file outside the repository gets no path, so `--sarif` refuses that build too. A bundle is one compile of one repository, so its decision paths resolve only in that repository.
