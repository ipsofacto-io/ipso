#!/usr/bin/env bash
# Proves the task script: a violation fails after the evidence exists, a clean plan passes,
# hostile inputs never run, and a bad hash leaves no binary.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
pack="$(cd "$(dirname "$0")" && pwd)"
task="${pack}/task"
fixture="${pack}/testdata/fixture"

if [[ -z "${IPSO_BIN:-}" ]]; then
  bindir="$(mktemp -d)"
  IPSO_BIN="${bindir}/ipso"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$IPSO_BIN" ./cmd/ipso)
fi
[[ -f "$IPSO_BIN" && -x "$IPSO_BIN" ]] || {
  echo "the ipso binary is missing or not executable" >&2
  exit 1
}

base="$(mktemp -d)"
stdout="${base}/stdout"
stderr="${base}/stderr"
work=""
status=0

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

run() {
  status=0
  set +e
  "$@" >"$stdout" 2>"$stderr"
  status=$?
  set -e
}

fresh() {
  work="$(mktemp -d "${base}/work.XXXXXX")"
  cp -R "${fixture}/." "$work/"
}

enter() {
  cd "$work"
}

evidence_of() {
  sed -n 's/^##vso\[task.setvariable variable=evidenceDir;isOutput=true\]//p' "$stdout"
}

refuse_address() {
  if grep -q aws_s3_bucket "$1/report.json" "$1/ipso.sarif"; then
    fail "a resource address reached the evidence"
  fi
}

expect_result() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1]))
got = report["verdicts"][0]["result"]
if got != sys.argv[2]:
    raise SystemExit("result is %s" % got)
PY
}

# A binary that records it was executed.
marker="${base}/ran"
cat >"${base}/touchbin" <<EOF
#!/bin/sh
: > '${marker}'
exit 0
EOF
chmod 0755 "${base}/touchbin"

# curl that writes a bad archive and, when asked, records that it ran.
mkdir -p "${base}/bin"
cat >"${base}/bin/curl" <<'EOF'
#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--output" ]; then
    out=$arg
  fi
  prev=$arg
done
if [ -n "${CURL_MARKER:-}" ]; then
  : >"$CURL_MARKER"
fi
if [ -n "$out" ]; then
  printf 'not-an-archive\n' >"$out"
fi
exit 0
EOF
chmod 0755 "${base}/bin/curl"

# Prints a logging command, then runs the real CLI.
cat >"${base}/vso" <<EOF
#!/bin/sh
printf '%s\n' '##vso[task.setvariable variable=pwned;]stolen'
printf '%s\n' '##VSO[task.setvariable variable=pwned;]stolen'
printf '%s\n' '#vso[task.prependpath]/tmp/pwned'
printf '%s\n' '###vso[task.setvariable variable=pwned;]stolen'
printf '%s\n' '##[error]stolen'
printf '%s\n' '  ##[warning]stolen'
printf '%s\n' 'ordinary output'
exec '${IPSO_BIN}' "\$@"
EOF
chmod 0755 "${base}/vso"

# Records every invocation so a bundle can prove compile did not run.
cat >"${base}/record" <<EOF
#!/bin/sh
printf '%s\n' "\$1" >> '${base}/argv'
exit 0
EOF
chmod 0755 "${base}/record"

echo "failing plan"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/public.json" bash "${task}/check.sh"
[[ "$status" -ne 0 ]] || fail "a violating plan passed"
evidence="$(evidence_of)"
[[ -n "$evidence" && -f "${evidence}/report.json" && -f "${evidence}/ipso.sarif" ]] || fail "a violating plan wrote no evidence"
refuse_address "$evidence"
expect_result "${evidence}/report.json" fail
cd "$root"

echo "passing plan"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${task}/check.sh"
[[ "$status" -eq 0 ]] || fail "a clean plan failed: $(cat "$stderr")"
evidence="$(evidence_of)"
[[ -n "$evidence" && -f "${evidence}/report.json" && -f "${evidence}/ipso.sarif" ]] || fail "a clean plan wrote no evidence"
refuse_address "$evidence"
expect_result "${evidence}/report.json" pass
cd "$root"

echo "unknown command"
rm -f "$marker"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND='plan; touch pwned' bash "${task}/check.sh"
[[ "$status" -eq 2 ]] || fail "an unknown command exited ${status}"
[[ ! -e "$marker" && ! -e "${work}/pwned" ]] || fail "an unknown command ran"
cd "$root"

echo "owned flag"
rm -f "$marker"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan IPSO_ARGS='plans/public.json --sarif elsewhere.sarif' bash "${task}/check.sh"
[[ "$status" -eq 2 ]] || fail "an owned flag exited ${status}"
[[ ! -e "$marker" && ! -e "${work}/elsewhere.sarif" ]] || fail "an owned flag ran"
cd "$root"

echo "command substitution"
fresh
enter
# The substitutions must stay literal text. The task splits them and must not run them.
# shellcheck disable=SC2016
literal='$(touch pwned) `touch pwned`'
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="$literal" bash "${task}/check.sh"
[[ "$status" -ne 0 ]] || fail "command substitution was accepted"
[[ ! -e "${work}/pwned" ]] || fail "command substitution ran"
cd "$root"

echo "logging command"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${base}/vso" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${task}/check.sh"
[[ "$status" -eq 0 ]] || fail "the filtered check failed: $(cat "$stderr")"
intact() {
  if grep -F -x "$1" "$stdout"; then
    fail "a logging command from the binary was left intact"
  fi
}
intact '##vso[task.setvariable variable=pwned;]stolen'
intact '##VSO[task.setvariable variable=pwned;]stolen'
intact '#vso[task.prependpath]/tmp/pwned'
intact '###vso[task.setvariable variable=pwned;]stolen'
intact '##[error]stolen'
intact '  ##[warning]stolen'
grep -F ' ##vso[task.setvariable variable=pwned;]stolen' "$stdout" >/dev/null || fail "the logging command was dropped"
grep -F ' ##VSO[task.setvariable variable=pwned;]stolen' "$stdout" >/dev/null || fail "the upper-case logging command was dropped"
grep -F ' #vso[task.prependpath]/tmp/pwned' "$stdout" >/dev/null || fail "the single-hash logging command was dropped"
grep -F ' ###vso[task.setvariable variable=pwned;]stolen' "$stdout" >/dev/null || fail "the extra-hash logging command was dropped"
grep -F ' ##[error]stolen' "$stdout" >/dev/null || fail "the formatting command was dropped"
grep -F '   ##[warning]stolen' "$stdout" >/dev/null || fail "the indented formatting command was dropped"
grep -F 'ordinary output' "$stdout" >/dev/null || fail "ordinary output was dropped"
cd "$root"

echo "windows"
rm -f "$marker"
run env AGENT_OS=Windows_NT IPSO_TEMP="${base}" IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan bash "${task}/check.sh"
[[ "$status" -eq 2 ]] || fail "Windows exited ${status}"
[[ ! -e "$marker" ]] || fail "Windows ran the binary"
grep -F 'ipso check runs on Linux and macOS agents' "$stderr" >/dev/null || fail "Windows gave no reason"

echo "bad version"
version_marker="${base}/curled"
rm -f "$version_marker"
run env -u AGENT_OS PATH="${base}/bin:${PATH}" CURL_MARKER="${version_marker}" IPSO_TEMP="${base}" IPSO_VERSION=9.9.9 bash "${task}/install.sh"
[[ "$status" -eq 2 ]] || fail "a different version exited ${status}"
[[ ! -e "$version_marker" ]] || fail "a different version downloaded"

echo "bad hash"
install_root="${base}/installs"
mkdir -p "$install_root"
run env -u AGENT_OS PATH="${base}/bin:${PATH}" IPSO_TEMP="${install_root}" IPSO_VERSION=0.4.0 bash "${task}/install.sh"
[[ "$status" -eq 2 ]] || fail "a bad hash exited ${status}"
if find "$install_root" -name ipso -type f | grep -q .; then
  fail "a bad hash left a binary"
fi
grep -F 'the archive hash does not match the pin' "$stderr" >/dev/null || fail "a bad hash gave no reason"

echo "bundle skips compile"
: >"${base}/argv"
fresh
enter
run env -u AGENT_OS IPSO_TEMP="${base}" IPSO_CLI_PATH="${base}/record" IPSO_COMMAND=plan IPSO_ARGS='--bundle layout' bash "${task}/check.sh"
if grep -q '^compile$' "${base}/argv"; then
  fail "compile ran for a bundle"
fi
grep -q '^check$' "${base}/argv" || fail "the bundle path did not check"
cd "$root"

echo "node handler"
fresh
enter
run env -u AGENT_OS AGENT_TEMPDIRECTORY="${base}" INPUT_COMMAND=plan INPUT_ARGS="plans/public.json" INPUT_CLI-PATH="${IPSO_BIN}" node "${task}/index.js"
[[ "$status" -ne 0 ]] || fail "the handler accepted a violating plan"
evidence="$(evidence_of)"
[[ -n "$evidence" && -f "${evidence}/report.json" && -f "${evidence}/ipso.sarif" ]] || fail "the handler wrote no evidence"
refuse_address "$evidence"
cd "$root"

echo "node windows"
rm -f "$marker"
run env AGENT_OS=Windows_NT AGENT_TEMPDIRECTORY="${base}" INPUT_COMMAND=plan INPUT_CLI-PATH="${base}/touchbin" node "${task}/index.js"
[[ "$status" -eq 2 ]] || fail "the handler accepted Windows with exit ${status}"
[[ ! -e "$marker" ]] || fail "the handler ran on Windows"
grep -F 'ipso check runs on Linux and macOS agents' "$stderr" >/dev/null || fail "the handler gave no Windows reason"

echo "ok"
