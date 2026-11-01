# Baselines

A baseline lets a team adopt a decision without fixing every existing violation first. Violations that exist when you create it are waived on later checks, and new ones still fail. The contract is ADR-0059 in `ipsofacto-io/ipso-spec`.

```bash
ipso compile
ipso baseline create semgrep .
ipso compile
ipso check semgrep .
```

`ipso baseline create|update` takes the same arguments as `ipso check`, including `--env` and `--input`, for `plan`, `checkov`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, and `eslint`. Run it once per engine, and commit `.ipso/baseline.json`. The new baseline applies after the next `ipso compile`, which copies it into the build the way it copies waivers. `--report`, `--sarif`, and `--bundle` are refused here.

## Create and update

- `create` adds an entry for each selected check that has none for this input. A clean check gets an empty entry, so running `create` again cannot absorb a later violation.
- `update` only removes fingerprints that no longer occur. It never adds one, so a baseline can only shrink. Run it after fixing violations.
- If a check cannot evaluate, nothing is written and the command exits `1`.
- Neither command changes a baseline stored on a server (ADR-0052).

## What a check reports

| Violations | Result | Exit code |
| --- | --- | --- |
| All covered | `waived`, printed as `waived (baseline: N)` | `0` |
| Some not covered | `fail`, and `violations` counts the uncovered ones | Follows the mode |

The terminal prints each uncovered violation and a baselined count. An error is never baselined, and an in-force waiver still covers the whole check. SARIF marks a baselined result at `note` level with a `Baselined:` message and a suppression. GitHub ignores suppressions, so that alert stays open at note severity until `update` removes its fingerprint and the violation is gone.

A local baseline has no deadline. It applies while its decision is in force.

## What cannot be baselined

`ipso check ci` results and Checkov's `check not reported` mean a control did not run, so a baseline would switch that control off. They stay failures, and `create` reports how many it skipped. `ipso baseline create ci` is refused. Use a waiver with an expiry instead.

## What a fingerprint covers

A fingerprint uses the rule and the file, module pair, or resource, numbered by occurrence, with no line number. A finding that moves keeps its fingerprint, and a baseline of n repeats waives at most n.

- Fixing one baselined finding and adding a new one in the same file waives the new one until `update` runs.
- When a new repeat of a baselined finding appears earlier in the same file, the earlier one is treated as covered and the later, older one is reported. The count is right, but the line shown may be the older finding.
- Reordering a decision's checks changes every fingerprint of those checks.
- `update` over fewer paths under the same input name drops fingerprints that are still valid, and those violations then fail. Give each path set its own `--input` to avoid this. To recover, remove that entry from the file and run `create` again.

## Several inputs

A check holds one baseline per input, and an input is named by `--env`, `--input`, or both. Use the same names on `ipso baseline` and on `ipso check`.

```bash
ipso baseline create plan prod.json --env prod
ipso baseline create plan staging.json --env staging
ipso baseline create plan stack-a.json --input stack-a
ipso baseline create semgrep services/a --input service-a
ipso compile
ipso check plan prod.json --env prod
```

- `--input` takes 1 to 64 letters, digits, `.`, `_`, or `-`, and starts with a letter or digit. `ipso check ci` does not take it.
- `create` and `update` touch only the input they name, so `update` for one environment leaves the others alone.
- A baseline never crosses inputs, even for the same resource address, because the names feed the fingerprint.
- A check run with different names than its baseline matches nothing, so its violations fail. If everything suddenly fails in CI, compare the `--env` and `--input` values first.
- Renaming an input means creating its baseline again.
- One decision holds at most 100,000 fingerprints across all its inputs.

## Protecting the file

Anyone who can commit can edit `.ipso/baseline.json` and waive a violation, so put it under `CODEOWNERS`. A signed bundle pins the baseline it was packed with, so editing the file afterwards does not change a `--bundle` check.

The file holds a random salt. Repository readers can see it, and it is never uploaded, so a server that stores fingerprints cannot confirm a guessed path. The manifest carries the salt too, so treat a bundle with a baseline as you would the repository. If you delete the file and create it again, the new salt no longer matches any baseline already stored on a server.
