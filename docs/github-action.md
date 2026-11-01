# GitHub Action

[`ipsofacto-io/ipso-action`](https://github.com/ipsofacto-io/ipso-action) runs one ipso check in a GitHub Actions job, uploads its SARIF file to code scanning, and keeps the SARIF file and the verdict report as a workflow artifact. It runs in your runner and calls no ipso service.

## Example workflow

This job checks a Terraform plan on every pull request. [`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples) runs the same workflow on a sample repository.

```yaml
name: ipso

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload the SARIF file to code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Write the plan
        run: |
          terraform init -input=false
          terraform plan -input=false -out p
          terraform show -json p > plan.json
      - uses: ipsofacto-io/ipso-action@<commit-sha> # pin a full commit SHA
        with:
          command: plan
          args: plan.json
          env: prod
```

Run the plan step without production secrets where you can. Only the verdicts and the plan hash reach the uploaded files, and the plan itself stays in the runner.

## What a step runs

A step runs `ipso check`, then `ipso compile`, then `ipso check <command> <args> --report <file> --sarif <file>`. The first command that fails stops the run. The uploads still run for whatever was written, and then the step fails.

`command` is one of the engine checks: `plan`, `ci`, `checkov`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, or `eslint`. `plan`, `ci`, `checkov`, `pulumi`, `cloudformation`, and `arm` need nothing more. The other commands need their pinned engine on `PATH`, so install it in an earlier step.

## More than one run

Use one step per named run. `env` and `input` become `--env` and `--input` and name the SARIF category, so these two runs do not close each other's alerts, as [baseline.md](baseline.md) and [sarif.md](sarif.md) describe:

```yaml
      - uses: ipsofacto-io/ipso-action@<commit-sha>
        with:
          command: plan
          args: stacks/network/plan.json
          env: prod
          input: network
      - uses: ipsofacto-io/ipso-action@<commit-sha>
        with:
          command: plan
          args: stacks/data/plan.json
          env: prod
          input: data
```

## Private repositories and forks

A private repository without code scanning sets `upload-sarif: "false"` and keeps the artifact. A pull request from a fork gets a read-only token, so the action skips the code scanning upload there and keeps the artifact.

The [action's README](https://github.com/ipsofacto-io/ipso-action#readme) lists every input and output and how the action verifies the CLI it installs.
