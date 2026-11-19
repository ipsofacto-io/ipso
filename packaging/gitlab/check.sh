#!/usr/bin/env bash
# Validates the decision files, compiles them, and runs one engine check. A failed check still
# leaves the report, the SARIF file, and the Code Quality report, then exits with that check's
# code. Usage errors exit 2 before ipso runs. GitLab tokens are unset before any child runs.
set -euo pipefail

fail() {
  echo "ipso: $1" >&2
  if [[ -n "${evidence:-}" && -d "$evidence" && ! -L "$evidence" && -n "${codequality:-}" && ! -e "$codequality" && ! -L "$codequality" ]]; then
    printf '%s\n' '[]' >"$codequality" || true
  fi
  exit 2
}

# A job that carries a GitLab token must not hand it to the installer, to ipso, or to the engines.
# CI_REPOSITORY_URL embeds CI_JOB_TOKEN. The dependency proxy and deploy passwords are that token too.
# DOCKER_AUTH_CONFIG can carry the same registry credential after those variables are unset.
unset CI_JOB_TOKEN GITLAB_TOKEN PRIVATE_TOKEN \
  CI_REGISTRY_USER CI_REGISTRY_PASSWORD \
  CI_DEPENDENCY_PROXY_USER CI_DEPENDENCY_PROXY_PASSWORD \
  CI_DEPLOY_USER CI_DEPLOY_PASSWORD \
  CI_JOB_JWT CI_JOB_JWT_V2 \
  CI_REPOSITORY_URL \
  DOCKER_AUTH_CONFIG

# Clear the published directory before any usage error returns. A checkout can already
# contain this path, and artifacts:when:always would otherwise upload it. A symlink is
# removed and not followed, so the job cannot delete or write the target.
evidence="ipso-evidence"
report="${evidence}/report.json"
sarif="${evidence}/ipso.sarif"
codequality="${evidence}/gl-code-quality.json"
if [[ -L "$evidence" ]]; then
  rm -f -- "$evidence" || fail "ipso-evidence could not be removed"
fi
if [[ -L "$evidence" ]]; then
  fail "ipso-evidence must not be a symlink"
fi
if [[ -e "$evidence" && ! -d "$evidence" ]]; then
  rm -f -- "$evidence" || fail "ipso-evidence could not be removed"
fi
rm -rf -- "$evidence"
if [[ -e "$evidence" || -L "$evidence" ]]; then
  fail "ipso-evidence could not be removed"
fi
mkdir -p -- "$evidence" || fail "ipso-evidence must be a directory"
if [[ -L "$evidence" || ! -d "$evidence" ]]; then
  fail "ipso-evidence must be a directory"
fi

case "${CI_RUNNER_EXECUTABLE_ARCH:-}" in
  windows/* | Windows/*) fail "ipso check runs on Linux and macOS runners" ;;
esac
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN* | Windows*) fail "ipso check runs on Linux and macOS runners" ;;
esac

case "${IPSO_COMMAND:-}" in
  plan | ci | checkov | snyk | wiz | sonarqube | dependabot | pulumi | cloudformation | arm | depcruise | semgrep | archunit | importlinter | kyverno | gatekeeper | eslint) ;;
  *) fail "command must be plan, ci, checkov, snyk, wiz, sonarqube, dependabot, pulumi, cloudformation, arm, depcruise, semgrep, archunit, importlinter, kyverno, gatekeeper, or eslint" ;;
esac
if [[ -z "${IPSO_CLI_PATH:-}" ]]; then
  case "${IPSO_COMMAND}" in
    snyk | wiz | sonarqube | dependabot)
      fail "that command is not in the pinned release"
      ;;
  esac
fi

if [[ -n "${IPSO_ARGS:-}" ]]; then
  [[ "${#IPSO_ARGS}" -le 512 ]] || fail "args is too long"
  [[ "${IPSO_ARGS}" =~ ^[A-Za-z0-9._/:=@+\ -]+$ ]] || fail "args has a forbidden character"
  [[ "${IPSO_ARGS}" =~ [^[:space:]] ]] || fail "args is empty"
fi
if [[ -n "${IPSO_ENV:-}" ]]; then
  [[ "${IPSO_ENV}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "env has a forbidden character"
fi
if [[ -n "${IPSO_INPUT:-}" ]]; then
  [[ "${IPSO_INPUT}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "input has a forbidden character"
fi
if [[ -n "${IPSO_CLI_PATH:-}" ]]; then
  [[ "${IPSO_CLI_PATH}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "cli-path has a forbidden character"
  [[ "${IPSO_CLI_PATH}" != *..* ]] || fail "cli-path has a forbidden character"
fi

args=()
if [[ -n "${IPSO_ARGS:-}" ]]; then
  # With no delimiter, read reaches end of input and returns 1, which is expected here.
  read -r -d '' -a args <<<"${IPSO_ARGS}" || true
fi
compile=true
for arg in ${args[@]+"${args[@]}"}; do
  case "${arg}" in
    --report | --report=* | --sarif | --sarif=*)
      fail "args cannot set --report or --sarif, the component writes those files"
      ;;
    --env | --env=* | --input | --input=*)
      fail "args cannot set --env or --input, use the env and input inputs"
      ;;
    --bundle | --bundle=*) compile=false ;;
  esac
done

here="$(cd "$(dirname "$0")" && pwd)"
if [[ -n "${IPSO_CLI_PATH:-}" ]]; then
  bin="${IPSO_CLI_PATH}"
else
  if [[ -z "${IPSO_TEMP:-}" ]]; then
    IPSO_TEMP="$(mktemp -d)"
    export IPSO_TEMP
  fi
  [[ "${IPSO_TEMP}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "IPSO_TEMP is missing or not a safe path"
  export IPSO_VERSION="${IPSO_VERSION:-0.4.0}"
  bin="$(bash "${here}/install.sh")"
fi
[[ -f "$bin" && -x "$bin" ]] || fail "the ipso binary is missing or not executable"

# GitLab writes the job token into the clone URL, and some runners put it in an http
# extraheader instead. Other https userinfo can carry a credential too, including a
# submodule checkout. Engines can read these files after the variables above are unset.
scrub_git_config() {
  local config="$1"
  local rewritten=""
  if [[ -L "$config" ]]; then
    fail "a git config must not be a symlink"
  fi
  [[ -f "$config" ]] || return 0
  if grep -Eqi 'https?://[^[:space:]@]+@|gitlab-ci-token:|[Ee][Xx][Tt][Rr][Aa][Hh][Ee][Aa][Dd][Ee][Rr]|Authorization:[[:space:]]*(Basic|Bearer)' "$config"; then
    rewritten="$(mktemp)"
    sed -E \
      -e 's#(https?://)[^[:space:]@]+@#\1#g' \
      -e '/[Ee][Xx][Tt][Rr][Aa][Hh][Ee][Aa][Dd][Ee][Rr]/d' \
      "$config" >"$rewritten" || fail "the git remote could not be rewritten"
    if grep -Eqi 'https?://[^[:space:]@]+@|gitlab-ci-token:|[Ee][Xx][Tt][Rr][Aa][Hh][Ee][Aa][Dd][Ee][Rr]|Authorization:[[:space:]]*(Basic|Bearer)' "$rewritten"; then
      rm -f "$rewritten"
      fail "the git remote still contains credentials"
    fi
    mv "$rewritten" "$config" || fail "the git remote could not be rewritten"
  fi
}
scrub_git_config .git/config
if [[ -d .git/modules ]]; then
  command -v find >/dev/null 2>&1 || fail "find is not installed"
  while IFS= read -r -d '' config; do
    scrub_git_config "$config"
  done < <(find .git/modules -name config -print0)
fi

write_codequality() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ipso: python3 is not installed" >&2
    return 2
  fi
  if ! python3 - "$1" "$2" <<'PY'
import json
import sys

severity = {"error": "blocker", "warning": "major", "note": "info"}
source, dest = sys.argv[1], sys.argv[2]


def die():
    sys.exit(1)


def path_ok(uri):
    if not isinstance(uri, str) or not uri or "\\" in uri or uri.startswith("/"):
        return False
    parts = uri.split("/")
    return all(part not in ("", ".", "..") for part in parts)


try:
    with open(source, encoding="utf-8") as handle:
        document = json.load(handle)
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        die()
    results = runs[0].get("results") or []
    if not isinstance(results, list):
        die()
    findings = []
    for result in results:
        if not isinstance(result, dict):
            die()
        level = result.get("level") or "warning"
        if level not in severity:
            die()
        message = (result.get("message") or {}).get("text")
        rule = result.get("ruleId")
        if not isinstance(message, str) or not message or "\n" in message or "\r" in message:
            die()
        if not isinstance(rule, str) or not rule or "\n" in rule or "\r" in rule:
            die()
        locations = result.get("locations") or []
        if not locations or not isinstance(locations[0], dict):
            die()
        physical = locations[0].get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if not path_ok(uri):
            die()
        line = (physical.get("region") or {}).get("startLine")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            die()
        fingerprint = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
        if not isinstance(fingerprint, str) or not fingerprint:
            die()
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:_-")
        if len(fingerprint) > 128 or any(char not in allowed for char in fingerprint):
            die()
        findings.append(
            {
                "description": message,
                "check_name": rule,
                "fingerprint": fingerprint,
                "severity": severity[level],
                "location": {"path": uri, "lines": {"begin": line}},
            }
        )
    with open(dest, "w", encoding="utf-8") as handle:
        json.dump(findings, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
except SystemExit:
    raise
except Exception:
    die()
PY
  then
    echo "ipso: the code quality report could not be written" >&2
    return 2
  fi
}

run_ipso() {
  set +e
  "$@"
  ipso_status=$?
  set -e
  return "$ipso_status"
}

flags=(--report "$report" --sarif "$sarif")
if [[ -n "${IPSO_ENV:-}" ]]; then
  flags+=(--env "${IPSO_ENV}")
fi
if [[ -n "${IPSO_INPUT:-}" ]]; then
  flags+=(--input "${IPSO_INPUT}")
fi

code=0
run_ipso "$bin" check || code=$?
if [[ "$code" -eq 0 && "$compile" == true ]]; then
  run_ipso "$bin" compile || code=$?
fi
if [[ "$code" -eq 0 ]]; then
  run_ipso "$bin" check "$IPSO_COMMAND" ${args[@]+"${args[@]}"} "${flags[@]}" || code=$?
fi

cq=0
if [[ -f "$sarif" ]]; then
  write_codequality "$sarif" "$codequality" || cq=$?
fi

if [[ "$code" -ne 0 ]]; then
  # The component always declares the Code Quality path. A failure before any SARIF file
  # exists has no findings, so publish an empty report. When a SARIF file exists and the
  # conversion failed, publish one fixed blocker. Do not copy the SARIF body, and do not
  # publish an empty report that would hide those findings.
  if [[ ! -e "$codequality" && -d "$evidence" && ! -L "$evidence" ]]; then
    if [[ -f "$sarif" ]]; then
      printf '%s\n' '[{"description":"ipso could not write the code quality report","check_name":"ipso/code-quality","fingerprint":"ipso-code-quality","severity":"blocker","location":{"path":"ipso-evidence/ipso.sarif","lines":{"begin":1}}}]' >"$codequality" || true
    else
      printf '%s\n' '[]' >"$codequality" || true
    fi
  fi
  echo "ipso did not pass, exit code ${code}" >&2
  exit "$code"
fi
if [[ "$cq" -ne 0 ]]; then
  exit "$cq"
fi
[[ -f "$report" && -f "$sarif" && -f "$codequality" ]] || fail "the check wrote no evidence"
