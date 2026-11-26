# GitLab CI component

GitLab CI/CD Catalog component ([`templates/check.yml`](templates/check.yml)) that runs `ipso check`, `ipso compile`, and one engine check from the root of a repository checkout.

## Usage

Publishing to the GitLab CI/CD Catalog is manual (this repository does not create the GitLab project). Once published, include the component in `.gitlab-ci.yml`:

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

- **Supported `command` values:** `plan`, `ci`, `checkov`, `snyk`, `wiz`, `sonarqube`, `dependabot`, `pulumi`, `cloudformation`, `arm`, `depcruise`, `semgrep`, `archunit`, `importlinter`, `kyverno`, `gatekeeper`, `eslint`.
- **Version pin note:** The default `ipso` `0.4.0` pin predates `snyk`, `wiz`, `sonarqube`, and `dependabot`; supply a newer binary via `cli-path` to use those commands.
- **Pipeline limits:** Include this component at most once per pipeline (job name: `ipso-check`). Default image: `ubuntu:24.04`. Windows runners are refused.

## Artifacts and merge request behavior

- A failed check exits non-zero, blocking merges when the GitLab project requires a successful pipeline (the component does not alter project settings).
- Every run writes `ipso-evidence/report.json`, `ipso-evidence/ipso.sarif`, and `ipso-evidence/gl-code-quality.json`.
- GitLab displays the Code Quality report on the merge request **Reports** tab even when the job fails (inline diff annotations require GitLab Ultimate). The component omits `artifacts:reports:sarif` because GitLab only ingests SARIF reports after a passing job.

## Security and verification

- **No GitLab tokens exposed:** Before downloading `ipso` or running checks, the component unsets `CI_JOB_TOKEN`, `CI_REPOSITORY_URL`, `GITLAB_TOKEN`, `PRIVATE_TOKEN`, registry/dependency-proxy/deploy passwords, `DOCKER_AUTH_CONFIG`, `CI_JOB_JWT`, and `CI_JOB_JWT_V2`, and strips HTTP userinfo and `extraheader` entries from `.git/config` and `.git/modules` configs.
- **Symlink hygiene:** Removes any symlink at `ipso-evidence` without following it and refuses symlinked git config files.
- **Verified install:** Downloads `ipso` `0.4.0` only after matching the pinned archive SHA-256 (skipped when `cli-path` is set) and makes no calls to any ipso service.

## Verification status

`ci / gitlab` in this repository verifies exit codes, output artifacts, and rejected inputs. This component has not been run on a live GitLab instance yet.
