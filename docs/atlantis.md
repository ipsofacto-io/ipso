# Atlantis

[Atlantis](https://www.runatlantis.io/) runs `terraform plan` and `terraform apply` from pull request comments. One server-side workflow adds `ipso check plan` to its plan stage, so a plan that breaks a blocking decision cannot be applied. ipso runs on the Atlantis server and calls no ipso service.

[`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples/tree/main/atlantis) runs this workflow on a real Atlantis whenever the sample changes, and you can run it on your machine with one command.

## Install

Put the `ipso` binary in your Atlantis image. The [sample `Dockerfile`](https://github.com/ipsofacto-io/examples/blob/main/atlantis/Dockerfile) installs a release and checks its sha256.

## The workflow

Add this to the [server-side repo config](https://www.runatlantis.io/docs/server-side-repo-config) that you pass with `--repo-config`:

```yaml
repos:
  - id: /.*/
    workflow: ipso
    allowed_overrides: []
    allow_custom_workflows: false

workflows:
  ipso:
    plan:
      steps:
        - init
        - plan
        - show
        - run: |
            status=0
            cd "$(git rev-parse --show-toplevel)" || status=$?
            if [ "$status" -eq 0 ]; then
              ipso check && ipso compile && ipso check plan "$SHOWFILE" || status=$?
            fi
            if [ "$status" -ne 0 ]; then
              rm -f "$PLANFILE"
            fi
            exit "$status"
```

`show` writes the plan as JSON to `$SHOWFILE` and keeps it out of the pull request comment. It runs the Terraform or OpenTofu binary that the project uses. The `run` step works from the repository root, because ipso reads `.ipso` and `docs/decisions` from there.

## What blocks

| Result | Exit | What Atlantis does |
| --- | --- | --- |
| A block-mode check has a violation that no waiver covers | `1` | Reports a plan error with the verdict lines. Removes the plan file, so `atlantis apply` has nothing to apply. |
| A check fails to evaluate, or a decision file is invalid | `1` | The same. ipso fails closed. |
| A warn-mode or advise-mode check has a violation | `0` | Reports a successful plan with the violation in the output. `atlantis apply` works. |
| A waiver in force covers a block-mode violation | `0` | Reports a successful plan with the check shown as `waived`. `atlantis apply` works. |

Removing the plan file is the block. Atlantis keeps the file when a later step of the plan stage fails, and it finds plans to apply by looking for those files. Do not drop that line.

A new commit or `atlantis plan` runs the whole stage again.

With `--parallel-plan`, projects of one pull request share a clone, so their `ipso compile` runs replace the same `.ipso/build` while another plan reads it. That fails closed, as a build error on a compliant plan. Pin a signed bundle, as below, or plan one project at a time.

To keep a pull request from merging on a failed plan, make the `atlantis/plan` status required on the default branch, and add `mergeable` to `apply_requirements`.

## Who can change the verdict

Atlantis runs the plan on the pull request's checkout, so `ipso compile` reads the decisions and policies from that same pull request. An author who can edit `docs/decisions` can add a waiver or lower a check's mode in the change that needs it. Pick one of these before you rely on the block:

- **Review the decisions.** Protect `docs/decisions` and your policy files with `CODEOWNERS` and required review, and add `approved` to `apply_requirements`. Atlantis counts any approval, so also require code owner review on the branch and add `mergeable`, or an unrelated approval lets the apply through.
- **Pin a signed bundle.** Build the decisions in a separate job with `ipso bundle pack` and `ipso bundle sign`, put the layout and the public key in your Atlantis image, and evaluate that instead of the checkout. The pull request can no longer change what it is checked against.

```yaml
        - run: |
            status=0
            ipso check plan "$SHOWFILE" \
              --bundle /etc/ipso/bundle \
              --digest sha256:<digest> \
              --key /etc/ipso/bundle.pub || status=$?
            if [ "$status" -ne 0 ]; then
              rm -f "$PLANFILE"
            fi
            exit "$status"
```

Keep `allowed_overrides: []` and `allow_custom_workflows: false` in both cases. A repository that can choose its workflow can drop this step, and a repository that can define one can run any command on your Atlantis server.

## Where plan data goes

The plan JSON stays in the Atlantis data directory, next to the plan file, until Atlantis deletes the pull request's workspace. ipso sends it nowhere.

Atlantis posts the output of a `run` step in the pull request comment. That includes ipso's verdict lines, with resource addresses and messages. The plan output Atlantis already posts names the same addresses, but a `deny` message can quote any attribute, including one Terraform marks as sensitive. Keep sensitive values out of your messages. If you cannot promise that, set `output: hide` on the step:

```yaml
        - run:
            command: |
              # the same script
            output: hide
```

The comment then shows only the exit status, the command, and the directory. The full output stays in the Atlantis job log.

## More than one environment

`--env` selects the decisions that apply in one environment. Use one server-side workflow per environment and choose it per repository with `workflow:`, or pass `--env "$WORKSPACE"` when your Terraform workspaces carry the environment names. Without `--env`, every plan check in force is evaluated.
