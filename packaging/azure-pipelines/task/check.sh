#!/usr/bin/env bash
# Validates the decision files, compiles them, and runs one engine check. A failed check still
# leaves the report and the SARIF file, then exits with that check's code. Usage errors exit 2
# before ipso runs. ipso's own output is filtered so a logging command cannot be emitted.
# Azure matches ##vso case-insensitively, with one or more leading hashes, and also ##[ lines.
set -euo pipefail

fail() {
  echo "##vso[task.logissue type=error]$1" >&2
  exit 2
}

# A pipeline that maps System.AccessToken, or a PAT, into this task must not hand it to the
# repository code ipso and the engines run.
unset SYSTEM_ACCESSTOKEN AZURE_DEVOPS_EXT_PAT AZURE_DEVOPS_PAT

case "${AGENT_OS:-}" in
  Windows_NT) fail "ipso check runs on Linux and macOS agents" ;;
esac
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN* | Windows*) fail "ipso check runs on Linux and macOS agents" ;;
esac

[[ "${IPSO_TEMP:-}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "IPSO_TEMP is missing or not a safe path"

case "${IPSO_COMMAND:-}" in
  plan | ci | checkov | pulumi | cloudformation | arm | depcruise | semgrep | archunit | importlinter | kyverno | gatekeeper | eslint) ;;
  *) fail "command must be plan, ci, checkov, pulumi, cloudformation, arm, depcruise, semgrep, archunit, importlinter, kyverno, gatekeeper, or eslint" ;;
esac

args=()
if [[ -n "${IPSO_ARGS:-}" ]]; then
  # With no delimiter, read reaches end of input and returns 1, which is expected here.
  read -r -d '' -a args <<<"${IPSO_ARGS}" || true
fi
compile=true
for arg in ${args[@]+"${args[@]}"}; do
  case "${arg}" in
    --report | --report=* | --sarif | --sarif=*)
      fail "args cannot set --report or --sarif, the task writes those files"
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
  export IPSO_VERSION="${IPSO_VERSION:-0.4.0}"
  bin="$(bash "${here}/install.sh")"
fi
[[ -f "$bin" && -x "$bin" ]] || fail "the ipso binary is missing or not executable"

evidence="$(mktemp -d "${IPSO_TEMP}/ipso-evidence.XXXXXX")"
report="${evidence}/report.json"
sarif="${evidence}/ipso.sarif"
[[ "$evidence" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "the evidence path is not safe to publish"

# Prefix a logging command from the repository so the agent prints it and does not run it.
filter() {
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^[[:space:]]*#+([Vv][Ss][Oo]\[|\[) ]]; then
      printf ' %s\n' "$line"
    else
      printf '%s\n' "$line"
    fi
  done
}

run_ipso() {
  set +e
  "$@" 2>&1 | filter
  ipso_status="${PIPESTATUS[0]}"
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

if [[ -f "$report" || -f "$sarif" ]]; then
  printf '##vso[task.setvariable variable=evidenceDir;isOutput=true]%s\n' "$evidence"
  [[ -f "$report" ]] && printf '##vso[task.setvariable variable=report;isOutput=true]%s\n' "$report"
  [[ -f "$sarif" ]] && printf '##vso[task.setvariable variable=sarif;isOutput=true]%s\n' "$sarif"
fi

if [[ "$code" -ne 0 ]]; then
  printf '##vso[task.logissue type=error]ipso did not pass, exit code %s\n' "$code" >&2
  exit "$code"
fi
[[ -f "$report" && -f "$sarif" ]] || fail "the check wrote no evidence"
