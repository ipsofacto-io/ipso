# Delivering accepted checks

`ipso deliver` brings a check that a person accepted in a control plane into a repository, so the check is part of what `ipso compile` builds. The contract is ADR-0120 in `ipsofacto-io/ipso-spec`, extended by ADR-0160 for `llm` checks and the `--repo` fetch, and by ADR-0165 for built-in templates.

## Use

The read is `GET /v1/accepted-checks?repo=<owner/name>`, under the role that reads the review queue, and it serves 50 checks a page, at most 100. `before` takes the id of the last check of the page. Delivery is repeatable, so each page can be delivered on its own.

With a CLI session from `ipso login`, or `IPSO_TOKEN`, the command fetches the first page itself:

```bash
ipso deliver --repo acme/api
ipso compile
git diff
```

Given a file or `-`, it opens no connection and reads no credential:

```bash
curl -sS "$IPSO/v1/accepted-checks?repo=acme/api" -H "Authorization: Bearer $TOKEN" | ipso deliver -
ipso deliver accepted-checks.json
```

## What it writes

For each check in force, `ipso deliver` adds one entry to the `checks` of the decision file whose `id` is the EDR id the answer names. What else it writes depends on the check.

An agent-edit Rego check is written to `.ipso/checks/<check id>.rego`:

```yaml
checks:
  - engine: opa
    target: agent-edit
    ref: .ipso/checks/0194f2a0-7b1c-7d3e-8a4f-1b2c3d4e5f60.rego
```

An `llm` check is written to `.ipso/checks/<check id>.llm.json`, and its entry carries `engine: llm`, its target, and its mode when the control plane set one.

A built-in template check writes no file. Its entry names the template, a Terraform plan template ([templates.md](templates.md)) or a Semgrep template ([semgrep-templates.md](semgrep-templates.md)):

```yaml
checks:
  - engine: opa
    target: terraform-plan
    ref: ipso:aws/ebs-encrypted
  - engine: semgrep
    ref: ipso:go/use-slog
```

A Rego or template entry has no `mode`, so the criticality of the decision decides. `.ipso` is a path the agent hooks protect, so an agent cannot edit the check that guards it. A delivered file holds the stored text, byte for byte. The decision file is edited through its frontmatter, so the body keeps its bytes, and comments and key order stay. The frontmatter is written again with two-space indents, so a file indented another way shows that change in the diff.

The command only adds. It never changes or removes a check, and it never replaces a file. A second run finds the entry and the file and writes nothing. A template entry that is already in the decision file, delivered or written by hand, counts as delivered.

## What stops it

Every check is verified before anything is written, and one problem stops the whole delivery with exit `1`:

- The answer is not JSON of accepted checks, is over 4 MiB, lists more than 1000 checks, or names an id that is not a lowercase UUID.
- The digest of a check does not match its Rego or its `llm` specification.
- The Rego fails the vet that `ipso compile` runs: Rego v1, a multi-value `deny`, no network built-in. An `llm` specification fails its validation.
- A template ref is not a template of this ipso version (`template-unknown`), or its engine and target are not the template's. An ipso older than the control plane can stop here, and upgrading ipso fixes it.
- A file in `.ipso/checks` already holds other bytes, or a path to a file it writes is a symlink.
- A decision file is invalid, or two records in force share an id.
- Rewriting a decision file would change anything but the one check.

## What it reports and skips

A check accepted for a version of its decision that is not the version in force is held: the command prints `held` on stderr with both versions and writes nothing. The same goes for a check whose decision names no EDR id, and for one whose EDR id no decision file in force in this checkout holds. These exit `0`.

## Review

A delivered Rego file is code from model output that a person accepted in the control plane. The digest shows that it arrived whole. It does not show that nobody changed both the Rego and the digest on the way. A template check is a choice a model made from the built-in list, and its rule is the tested template of this ipso version. Review the files and the decision file in a pull request, as for any decision change.
