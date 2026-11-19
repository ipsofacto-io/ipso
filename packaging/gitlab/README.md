# GitLab CI component

`templates/check.yml` is a GitLab CI/CD Catalog component. It runs `ipso check`, `ipso compile`, and one engine check from the root of the checkout. A failed check exits non-zero, which blocks a merge request when the project requires a successful pipeline. The component does not change that project setting.

The job writes `ipso-evidence/report.json`, `ipso-evidence/ipso.sarif`, and `ipso-evidence/gl-code-quality.json`. GitLab shows the Code Quality report on the merge request Reports tab, including when the job fails. Inline annotations on the diff are a GitLab Ultimate feature of that same report. The component does not set `artifacts:reports:sarif`, because GitLab ingests those findings only after a successful job.

The component holds no GitLab token. It unsets `CI_JOB_TOKEN`, `CI_REPOSITORY_URL` (the clone URL embeds that token), `GITLAB_TOKEN`, `PRIVATE_TOKEN`, the registry, dependency-proxy, and deploy passwords, `DOCKER_AUTH_CONFIG`, and `CI_JOB_JWT` and `CI_JOB_JWT_V2` before it downloads ipso or runs a check. It also removes userinfo from every http and https URL in `.git/config` and in each `.git/modules` config, removes http extraheader lines, removes a symlink at `ipso-evidence` without following it, and refuses a symlink at those config files. It does not call an ipso service. It installs ipso 0.4.0 only, after the archive sha256 matches the pin in this directory. `cli-path` skips that download. Windows runners are refused. The default image is `ubuntu:24.04`.

Publishing the component to the CI/CD Catalog is manual. This repository does not create the GitLab project. After that release, a pipeline includes the component with the published project path and version:

```yaml
include:
  - component: $CI_SERVER_FQDN/<group>/<project>/check@<version>
    inputs:
      command: plan
      args: plans/plan.json

workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

`command` is one of `plan`, `ci`, `checkov`, `snyk`, `wiz`, `sonarqube`, `dependabot`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, or `eslint`. The 0.4.0 pin does not contain `snyk`, `wiz`, `sonarqube`, or `dependabot`. Those need `cli-path`. One pipeline can include this component once. The job name is `ipso-check`.

`ci / gitlab` in this repository proves the exit code, the files, and the refused inputs. A GitLab project has not run this component.
