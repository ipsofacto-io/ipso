# Local MCP server

`ipso mcp` serves the decisions of one checkout to an AI coding agent over stdio. The contract is ADR-0073 in `ipsofacto-io/ipso-spec`. It targets MCP 2026-07-28 and also answers clients on 2025-11-25, 2025-06-18, and 2025-03-26. It needs no login and makes no network call.

The server reads the directory it starts in, so the client must start it at the repository root.

## Connect a client

Claude Code:

```bash
claude mcp add --transport stdio ipso -- ipso mcp
```

Cursor, in `.cursor/mcp.json`:

```json
{ "mcpServers": { "ipso": { "command": "ipso", "args": ["mcp"] } } }
```

Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.ipso]
command = "ipso"
args = ["mcp"]
```

The server has connected in Claude Code with `claude mcp list` and listed its tools in `cursor-agent mcp list-tools`. It has not run in Codex.

## Tools

| Tool | Input | Output | Side effect |
| --- | --- | --- | --- |
| `decisions.applicable` | `repo`, `paths`, `env`, `intent` | decisions in force, with checks and state | none |
| `decisions.get` | `ref`, `as_of_valid`, `as_of_tx` | one decision and whether it is in force | none |
| `checks.evaluate` | `diff` or `plan`, `env` | verdict lines, `blocked`, SARIF, `not_evaluated` | none |
| `decisions.propose` | `title`, `statement`, `rationale`, `verification`, `paths`, `env`, `session_ref` | proposal id and path | writes one new file |

A field left out of `decisions.applicable` widens the answer, so pass the paths and environment the work touches. `intent` does not change the answer. An invalid decision file makes the tool fail, because a partial list would read as "nothing else applies". `decisions.get` refuses `as_of_tx`, because only a registry knows what was recorded when.

A record tagged `sensitive` comes back with no title, text, or sources.

## Evaluating an edit

`checks.evaluate` with `plan` runs `ipso check plan`. With `diff`, it applies the patch in memory and runs the checks with `target: agent-edit` on the resulting files. Context that does not match the file is an error. Nothing is written. Run `ipso compile` first.

An `agent-edit` check is repository Rego that reads one proposed edit:

```yaml
checks:
  - engine: opa
    target: agent-edit
    ref: policy/no-float.rego
    mode: block
```

```rego
package ipso.nofloat

import rego.v1

deny contains "money is a float" if {
    contains(input.content, "float64")
}
```

| Input field | Meaning |
| --- | --- |
| `input.tool` | What makes the change, such as `patch` |
| `input.path` | Slash-separated path from the repository root |
| `input.content` | The whole file after the edit |
| `input.added` | Only the new lines |
| `input.command` | A shell command, which has no path |

The decision's `paths` limit which files reach the check. Other engines do not run here, because they need a tree and can take many seconds. `not_evaluated` names those checks, so a clean verdict is not read as covering them. CI still runs them.

## Proposals

`decisions.propose` writes a new EDR file with `status: proposed`, for example `docs/decisions/proposed/use-int64-for-money-a1b2c3.md`, and a person approves it by changing the status in a pull request. No input reaches the status, owner, checks, or waivers. A proposal is not in force, so `ipso compile`, `ipso rules generate`, and `decisions.applicable` leave it out. Text that starts a heading or holds a control character is refused, and the file is never written over an existing one or through a symlink.
