# Delivering accepted checks

`ipso deliver` brings an agent-edit check that a person accepted in a control plane into a repository, so the check is part of what `ipso compile` builds. The contract is ADR-0120 in `ipsofacto-io/ipso-spec`. The command opens no connection and holds no credential.

## Use

Fetch the answer with your own token, then pipe it in. The read is `GET /v1/accepted-checks?repo=<owner/name>`, under the role that reads the review queue, and it serves 50 checks a page, at most 100. `before` takes the id of the last check of the page. Delivery is repeatable, so each page can be piped in on its own.

```bash
curl -sS "$IPSO/v1/accepted-checks?repo=acme/api" -H "Authorization: Bearer $TOKEN" | ipso deliver -
ipso compile
git diff
```

A file works too: `ipso deliver accepted-checks.json`.

## What it writes

For each check in force, `ipso deliver` writes the Rego to `.ipso/checks/<check id>.rego` and adds this entry to the `checks` of the decision file whose `id` is the EDR id the answer names:

```yaml
checks:
  - engine: opa
    target: agent-edit
    ref: .ipso/checks/0194f2a0-7b1c-7d3e-8a4f-1b2c3d4e5f60.rego
```

The entry has no `mode`, so the criticality of the decision decides. `.ipso` is a path the agent hooks protect, so an agent cannot edit the check that guards it. The Rego is the stored Rego, byte for byte. The decision file is edited through its frontmatter, so the body keeps its bytes, and comments and key order stay. The frontmatter is written again with two-space indents, so a file indented another way shows that change in the diff.

The command only adds. It never changes or removes a check, and it never replaces a file. A second run finds the entry and the file and writes nothing.

## What stops it

Every check is verified before anything is written, and one problem stops the whole delivery with exit `1`:

- The answer is not JSON of accepted checks, is over 4 MiB, lists more than 1000 checks, or names an id that is not a lowercase UUID.
- The digest of a check does not match its Rego.
- The Rego fails the vet that `ipso compile` runs: Rego v1, a multi-value `deny`, no network built-in.
- A file in `.ipso/checks` already holds other bytes, or a path to a file it writes is a symlink.
- A decision file is invalid, or two records in force share an id.
- Rewriting a decision file would change anything but the one check.

## What it reports and skips

A check accepted for a version of its decision that is not the version in force is held: the command prints `held` on stderr with both versions and writes nothing. The same goes for a check whose decision names no EDR id, and for one whose EDR id no decision file in force in this checkout holds. These exit `0`.

## Review

The delivered Rego is code from model output that a person accepted in the control plane. The digest shows that it arrived whole. It does not show that nobody changed both the Rego and the digest on the way. Review the Rego and the decision file in a pull request, as for any decision change.
