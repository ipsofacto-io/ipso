# Azure Pipelines

The task in [`packaging/azure-pipelines`](../packaging/azure-pipelines) runs one ipso check on a Linux or macOS agent. It writes the SARIF file and the verdict report under the agent temp directory, and the pipeline publishes that directory. It runs in your agent and calls no ipso service. It holds no PAT and no `System.AccessToken`.

Windows agents are refused. The task installs ipso 0.4.0 only, after the sha256 in [`task/checksums.txt`](../packaging/azure-pipelines/task/checksums.txt) matches the archive. `cli-path` skips that install for a binary you already placed on the agent, and that binary is not hashed.

Publishing the extension to the Marketplace is a manual step. Until that upload exists, a pipeline cannot reference `IpsoCheck@1`.

## Example pipeline

This job checks a plan that breaks a blocking decision, so the task fails the job. The publish step still runs. [`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples) has the same pipeline. It has not been run on Azure DevOps. `ci / azure-pipelines` in this repository proves the exit code and the files.

```yaml
trigger:
  - main

pr:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    persistCredentials: false
  - task: IpsoCheck@1
    name: ipso
    inputs:
      command: plan
      args: azure/plans/public.json
  - task: PublishPipelineArtifact@1
    condition: succeededOrFailed()
    inputs:
      targetPath: $(ipso.evidenceDir)
      artifact: ipso-evidence
```

Run the job without production secrets where you can. The report carries the plan hash and the verdicts. Resource addresses stay in the agent log, not in the published files.

## What a step runs

A step runs `ipso check`, then `ipso compile`, then `ipso check <command> <args> --report <file> --sarif <file>`. `--bundle` in `args` skips the compile. The first command that fails stops the run. When the check wrote files, they are still there, and then the task exits with the check's code.

`command` is one of `plan`, `ci`, `checkov`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, or `eslint`. `args` is split on whitespace and no shell expands it. `args` cannot set `--report`, `--sarif`, `--env`, or `--input`. `env` and `input` become those flags.

`depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, and `eslint` need their pinned engine on `PATH`. Install it in an earlier step. The task does not install engines.

## More than one run

Use one job per named run, or publish each evidence directory under its own artifact name. Two publishes of `ipso-evidence` in one job fail the second upload.

```yaml
  - task: IpsoCheck@1
    name: network
    inputs:
      command: plan
      args: stacks/network/plan.json
      env: prod
      input: network
  - task: PublishPipelineArtifact@1
    condition: succeededOrFailed()
    inputs:
      targetPath: $(network.evidenceDir)
      artifact: ipso-evidence-network
```

## Private agents

An agent without `sha256sum` or `shasum` cannot install the pinned release. An air-gapped agent sets `cli-path` to a binary it already mirrored. That path skips the hash, so the pipeline is trusting its own file.
