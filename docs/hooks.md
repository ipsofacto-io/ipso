# Agent hooks

`ipso hook <agent> [event]` answers an agent's hooks, for `claude-code`, `codex`, `copilot`, `cursor`, and `kiro`. `ipsofacto-io/agent-plugins` holds the plugin and install files. The contracts are ADR-0074 and ADR-0075 in `ipsofacto-io/ipso-spec`.

The hook acts only in a repository with an `.ipso` directory, so run `ipso init` first. It decides on this machine with no LLM and makes no network call.

## Enforcement per agent

Every agent gets the same decision. What it can do with that decision differs, so this is what a person can rely on:

| Agent | Hook | A `block` violation | A `warn` violation, a protected path, or a check that cannot run | At stop | With no `ipso` binary |
| --- | --- | --- | --- | --- | --- |
| Claude Code | `PreToolUse` | Denied | Asks a person | Sent back once | Fails open with a notice |
| Codex | `PreToolUse` on `Bash` and `apply_patch` | Denied | Denied, because `ask` fails the hook and runs the tool | Sent back once | Not documented |
| Copilot CLI | `preToolUse` | Denied | Asks a person. Denied in autopilot | Sent back once | Fails closed: every tool call stops |
| Copilot cloud agent | `preToolUse` from `.github/hooks` | Denied | Denied | Sent back once | Fails closed, so install `ipso` in the setup steps |
| Cursor | `preToolUse` and `beforeShellExecution` | Denied | An edit is denied, because `preToolUse` does not enforce `ask`. A shell command asks a person | Sent back once as a follow-up | Fails open |
| Kiro | `PreToolUse` | Refused with exit 2 | Refused, because a hook cannot ask | Flagged in context only | Not documented for this trigger |
| Copilot code review, Devin, and anything else with no hook | None | Reported by the PR check | Reported by the PR check | None | Not applicable |

Only Claude Code passes on an `advise` message at edit time. Codex describes its own hooks as a guardrail and not an enforcement boundary. Project hooks there load only in a trusted project and after review with `/hooks`. A Copilot hook that times out fails open. Cursor and Kiro do not document the input of their file tools, so the hook reads a call by its shape, and a tool whose shape it does not recognize gets no answer.

None of these four has run with `ipso hook` in a live session. The tests feed each vendor's documented events to the command.

## Without a hook: the PR check

A hook is a convenience on one machine. The gate is a required check on the pull request, for every agent and every person, with or without hooks:

```yaml
- run: ipso check
- run: ipso compile
- run: ipso rules check
- run: ipso check semgrep .
```

`ipsofacto-io/ipso-action` runs an engine check and uploads its SARIF, as [github-action.md](github-action.md) shows. Rules files from [rules-files.md](rules-files.md) tell an agent with no hook what is in force, and they are advisory.

## PreToolUse

For a tool that edits a file or runs a shell command, including `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Bash`, and Codex's `apply_patch`, the hook works out the content after the edit and runs the `agent-edit` checks whose scope covers the file. `docs/mcp.md` shows how to write one. A shell command has no path, so it reaches every `agent-edit` check through `input.command`.

| Situation | Answer |
| --- | --- |
| No violation | Nothing. The hook never says allow, because that would skip a person's own permission rules |
| A `block` check has an uncovered violation | Deny, with the message and the path of the decision record |
| A `warn` check has an uncovered violation | Ask a person, where the agent can |
| An `advise` check has an uncovered violation | Nothing stops the edit, and the agent gets the message as context |
| A waiver covers the violation | Nothing |
| A check cannot evaluate, or the build or bundle cannot be loaded | Ask a person |
| The edit touches `.ipso` or a decision record | Ask a person, through links too |
| A shell command names `.ipso/` or the literal start of a `decisions` glob | Ask a person |

A person decides what happens to a decision. An agent uses `decisions.propose` instead.

The measured path is one process per edit with 20 `agent-edit` checks and a 24 KB file: p95 about 50 ms on a laptop. `ci / hook-latency` fails at 300 ms.

## Stop

The hook checks the working tree:

- every decision file, as `ipso check` does
- `agent-edit` checks on what `git status` reports as changed
- `ipso check semgrep`, `depcruise`, `eslint`, `kyverno`, and `gatekeeper` on `.`, for engines the build has checks for

Blocking violations go back to the agent to fix. When the agent is already continuing because of this hook, the hook reports them and lets the session end, so the two cannot loop. An engine that is not installed is a note and not a violation. `archunit`, `importlinter`, and the checks that need a plan or an evidence file do not run here. CI runs them.

## SessionStart

Without a signed bundle, the hook runs `ipso compile`, because git ignores `.ipso/build` and a fresh clone has none. It then states the decisions in force by slug, title, criticality, and globs, cut at 9000 characters. A record tagged `sensitive` shows only its slug. If compile fails, edits stop for a person until it succeeds.

## A signed bundle

Pass `--bundle`, `--digest`, and `--key`, or set the plugin options `bundle_dir`, `bundle_digest`, and `bundle_key`. The bundle is verified on every edit. A bad pin or signature asks a person. With a bundle, `SessionStart` does not compile, and the engines in `Stop` do not run, because they read the local build.

## Limits

The hook guards a cooperating agent and is not a sandbox. A shell command can hide what it touches, and a build the agent replaced from outside these tools is only caught by a signed bundle. A missing `ipso` binary is a non-blocking error in Claude Code, so the hook fails open with a notice. CI remains the gate.

The hook has been tested against the event formats the vendors document. It has not run in a live session of any agent.
