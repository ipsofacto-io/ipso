# Spacelift, env0, and Scalr

Spacelift, env0, and Scalr run Terraform or OpenTofu on their own workers and let you run commands around each phase. A hook runs `ipso check plan` on the worker, against the run's own plan, and a non-zero exit stops the run. There is no webhook, no ipso service, and no token, so the plan stays on the worker.

> Validation status: none of these has run on the vendor's platform yet. [`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples/tree/main/platforms) runs the exact hook commands on a real Terraform plan and checks their exit codes, and the vendor column in each section says what the vendor documents. Validate on a test stack before you rely on the block, as the last section describes.

## What every platform needs

**The CLI on the worker.** Bake `ipso` into your runner image. An install inside a hook can be lost between phases: Spacelift runs the phases after a pause in a new container.

**A decision the run cannot edit.** The hook runs on the checkout of the run, so `ipso compile` reads that checkout's decisions. On a proposed run that is the pull request's own version. Pin a signed bundle instead when the block has to hold against the author:

```sh
ipso check plan plan.json --bundle /opt/ipso/bundle --digest sha256:<digest> --key /opt/ipso/bundle.pub
```

Bake the layout and the public key into the runner image, and build the bundle in a job you trust, as [docs/atlantis.md](atlantis.md) describes.

**A hook the run cannot edit.** A file in the repository can be changed by the same pull request. Set the hook in the platform's own settings, where the platform offers that, and restrict who can change them.

**Least privilege.** The hook needs no token and makes no network call. Do not give ipso cloud credentials: it reads a file. Workers usually hold cloud credentials for Terraform, so the hook's output is the only thing to watch. ipso prints resource addresses and messages to the run log, and a policy can quote an attribute. Keep sensitive values out of `deny` messages.

## Spacelift

Set the hook on the stack, under **Behavior**, or in `.spacelift/config.yml` if you accept that the same pull request can change it.

```yaml
version: "2"
stacks:
  network:
    project_root: terraform
    before_apply:
      - terraform show -json spacelift.plan > /tmp/plan.json && cd "$(git rev-parse --show-toplevel)" && ipso check && ipso compile && ipso check plan /tmp/plan.json
```

| Point | What Spacelift documents |
| --- | --- |
| Where it runs | Hooks run on the worker, in the same shell session as the phase, in the project root |
| What stops the run | "If a "before" hook fails (non-zero exit code), the corresponding phase will not execute." |
| The plan file | `spacelift.plan`, expected in the project root after planning. ipso depends on this name. |
| Multi-line hooks | Keep the command on one line with `&&`. Spacelift warns that a newline can hide a non-zero exit |

`before_apply` is the block. It does not run on a proposed run, because a proposed run never applies. To report on pull requests too, add the same line to `after_plan`, and test what a failure there does on your stack.

Spacelift's own [plan policies](https://docs.spacelift.io/concepts/policy/terraform-plan-policy) are Rego too, and they read Spacelift's input, not `.ipso/build`. They stay available beside this hook.

## env0

Set the flow in `env0.yml` beside the template, or as a project-level flow that the template's repository cannot change.

```yaml
version: 2
deploy:
  steps:
    terraformPlan:
      after:
        - cd "$ENV0_ROOT_DIR" && ipso check && ipso compile && ipso check plan "${ENV0_TF_PLAN_JSON:?env0 did not provide the plan JSON}" 1>&2
```

For OpenTofu, the step is `opentofuPlan`.

| Point | What env0 documents |
| --- | --- |
| Where it runs | On the deployment's worker, in the directory that holds the YAML file |
| What stops the run | "If any command in your custom flow returns a non-zero exit code, the env zero deployment will stop on a 'Failed' status." |
| The plan file | `ENV0_TF_PLAN_JSON`, a path to the plan as JSON. `${...:?}` fails closed if it is not set. |
| The message | env0 shows `stderr` as the deployment error, so `1>&2` puts the verdict lines there |

## Scalr

Add the hook in the workspace settings, or in the hooks registry to share it across workspaces. Both are outside the repository. Scalr can also run hooks that ship with a self-hosted agent, which apply to every run on that agent.

Put this in a script in the directory the workspace points to, or download it at runtime, and make it executable:

```sh
#!/bin/sh
set -eu
terraform show -json /opt/data/terraform.tfplan.bin > /tmp/plan.json
cd "$(git rev-parse --show-toplevel)"
ipso check
ipso compile
ipso check plan /tmp/plan.json
```

Attach it at **pre-apply**, and at **post-plan** if you want the verdict on plan-only runs too.

| Point | What Scalr documents |
| --- | --- |
| Where it runs | In the same container as Terraform, with its output in the run's console |
| What stops the run | A hook that exits non-zero fails the run at that point, according to Scalr's learning center. The hooks reference does not state it, so this is the first thing to validate. |
| The plan file | `/opt/data/terraform.tfplan.bin` in the docs' example |
| Which operation | `SCALR_TERRAFORM_OPERATION` names plan or apply. `post-plan` runs whether or not the plan succeeded |

Scalr's checkout may not be a git repository in every workspace type. If `git rev-parse` fails, the hook fails, which is the safe direction: change the `cd` to the path your workspace uses.

## Validate it on a test stack

For each platform you adopt:

1. Create a throwaway stack, environment, or workspace with the hook and no real credentials. `terraform_data` needs no provider.
2. Start a run that breaks a blocking decision. The run should stop with the verdict lines in its log, and no apply should happen.
3. Start a run that breaks only a warning decision. The run should go on, with the warning in its log.
4. Break a decision file. The run should stop.

Record what you saw. A hook that is silently skipped looks the same as one that passed, so confirm the verdict lines are in the log.
