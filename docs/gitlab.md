# GitLab

The component in [`packaging/gitlab`](../packaging/gitlab) runs one ipso check on a Linux or macOS runner. A failed check exits non-zero. A project that requires a successful pipeline then blocks the merge request. The component does not change that project setting. It writes `ipso-evidence/report.json`, `ipso-evidence/ipso.sarif`, and `ipso-evidence/gl-code-quality.json`. GitLab shows the Code Quality report on the merge request Reports tab, including when the job fails. Inline annotations on the diff are a GitLab Ultimate feature of that same report. The component does not set `artifacts:reports:sarif`, because GitLab ingests those findings only after a successful job.

It runs in your runner and calls no ipso service. It unsets the job token, the clone URL that embeds that token, `DOCKER_AUTH_CONFIG`, and the registry, dependency-proxy, and deploy passwords before it downloads ipso or runs a check. Before ipso runs, it removes userinfo from every http and https URL in `.git/config` and in each submodule config under `.git/modules`, it removes http extraheader lines, it removes a symlink at `ipso-evidence` without following it, and it refuses a symlink at those config files. Windows runners are refused. The component installs ipso 0.4.0 only, after the sha256 in [`checksums.txt`](../packaging/gitlab/checksums.txt) matches the archive. `cli-path` skips that install for a binary you already placed on the runner, and that binary is not hashed.

Publishing the component to the CI/CD Catalog is a manual step. Until that release exists, a pipeline cannot include it. The example below uses the path and version of that release.

## Example pipeline

This job checks a plan that breaks a blocking decision, so the job fails. The Code Quality report is still published. [`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples) has the same pipeline. It has not been run on GitLab. `ci / gitlab` in this repository proves the exit code and the files.

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

include:
  - component: $CI_SERVER_FQDN/<group>/<project>/check@<version>
    inputs:
      command: plan
      args: gitlab/plans/public.json
```

Run the job without production secrets where you can. The report carries the plan hash and the verdicts. Resource addresses stay in the runner log, not in the published files. A check that passes still fails when `python3` is missing, because the Code Quality report is required. The default image is `ubuntu:24.04`.

## What the job runs

The job runs `ipso check`, then `ipso compile`, then `ipso check <command> <args> --report <file> --sarif <file>`. `--bundle` in `args` skips the compile. The first command that fails stops the run. When the check wrote files, they are still there, and then the job exits with the check's code. When check or compile fails before a SARIF file exists, the job writes an empty Code Quality report and still exits with that failure's code. When a SARIF file exists and the conversion fails, the job writes one blocker that says the report could not be written, without copying the SARIF body, and it still exits with the check's code.

`command` is one of `plan`, `ci`, `checkov`, `snyk`, `wiz`, `sonarqube`, `dependabot`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, or `eslint`. `args` is split on whitespace and no shell expands it. `args` cannot set `--report`, `--sarif`, `--env`, or `--input`. `env` and `input` become those flags. `snyk`, `wiz`, `sonarqube`, and `dependabot` read an evidence file the job wrote. The component does not run those scanners. The 0.4.0 release the component installs does not contain those four commands, so set `cli-path` to a binary that does.

`depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, and `eslint` need their pinned engine on `PATH`. Install it in an earlier job. The component does not install engines.

## More than one run

Include the component once per pipeline. The job name is `ipso-check`, so a second include fails the pipeline. Use one pipeline per named run.

## Private runners

A runner without `sha256sum` or `shasum` cannot install the pinned release. An air-gapped runner sets `cli-path` to a binary it already mirrored. That path skips the hash, so the pipeline is trusting its own file. A runner without `python3` cannot write the Code Quality report.
