# Agent rules files

`ipso rules generate` writes the decisions in force into the files AI coding agents read. The contract is ADR-0072 in `ipsofacto-io/ipso-spec`.

```bash
ipso rules generate
ipso rules check
```

Rules files are advisory context, and an agent can ignore them. Enforcement is the agent hook and the checks in CI.

## What is written

| Agent | File | How it is scoped |
| --- | --- | --- |
| Codex and others that read it | `AGENTS.md` | Where the file sits |
| Claude Code | `CLAUDE.md` | Where the file sits |
| Gemini CLI | `GEMINI.md` | Where the file sits |
| GitHub Copilot | `.github/copilot-instructions.md` | Decisions for the whole repository |
| GitHub Copilot | `.github/instructions/ipso-<slug>.instructions.md` | `applyTo` |
| Cursor | `.cursor/rules/ipso-<slug>.mdc` | `globs`, or `alwaysApply` for the whole repository |
| Kiro | `.kiro/steering/ipso-<slug>.md` | `fileMatchPattern`, or `inclusion: always` for the whole repository |

A scope item with no `paths` covers the whole repository. Otherwise each glob in `paths` picks its directory: `AGENTS.md`, `CLAUDE.md`, and `GEMINI.md` are written to the deepest directory that exists on the literal start of the glob. `services/payments/**` goes to `services/payments/` when that directory exists. `**/*.tf` has no literal start and goes to the root. The file always states the globs.

Only records in force are written, by the same status and date rule as `ipso compile`. Each entry holds the title, slug, criticality, state, globs, environments, the path of the record, and the Decision section, cut at 2000 characters. Context, Alternatives considered, Consequences, and Verification are never written.

## Hand-written text

`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and `.github/copilot-instructions.md` often hold text people wrote, so the command owns one marked block and keeps everything around it. Do not edit inside the markers. When a file has no block left and no other text, it is removed.

The `ipso-<slug>` files are owned whole. Each carries a marker line, and a later run replaces or removes only files with that marker. A file at one of those paths without the marker stops the command.

## Sensitive decisions

A record with the tag `sensitive` has its title and text left out. The generated entry holds its slug, criticality, state, globs, and the path of the record.

```yaml
tags: [sensitive]
```

## Keep the files current

`ipso rules check` writes nothing. It prints `<path>: out of date` for each file that differs and exits `1`, so it can run in CI next to `ipso check`:

```yaml
- run: ipso rules check
```

A decision can also go out of force by date, so the check can fail on a day when no file changed. Run `ipso rules generate` and commit the result.

## Refusals

The command exits `1` and writes nothing when:

- any decision file is invalid, so a generated file never reflects part of the decisions
- a file has a block whose markers do not pair, or more than one block
- a generated path holds a symlink, or a symlink is on the way to it
- two records in force share a slug or an id
- a file it would write matches a `decisions` glob in the config, so it would be read as a decision. A nested memory file instead stops at the nearest directory outside the glob
- a glob holds a character outside `A-Za-z0-9._/*?@+~=-`, or leaves the repository

The command reads no network service. A record's `repo` and `org` are not compared with the checkout, the same way `ipso compile` treats them. `.git`, `.ipso`, `node_modules`, and `vendor` are not searched for old blocks and do not get new ones.
