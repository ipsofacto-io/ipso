#!/usr/bin/env bash
# Proves the component script: a violation fails after the evidence exists, a clean plan passes,
# hostile inputs never run, and a bad hash leaves no binary.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
pack="$(cd "$(dirname "$0")" && pwd)"
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

refuse_address() {
  if grep -q aws_s3_bucket "$1/report.json" "$1/ipso.sarif" "$1/gl-code-quality.json"; then
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

expect_blocker() {
  python3 - "$1" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc, list) or len(doc) != 1:
    raise SystemExit("expected one code quality finding")
item = doc[0]
keys = {"description", "check_name", "fingerprint", "severity", "location"}
if set(item) != keys:
    raise SystemExit("unexpected code quality keys")
if item["severity"] != "blocker":
    raise SystemExit("severity is %s" % item["severity"])
location = item["location"]
if set(location) != {"path", "lines"}:
    raise SystemExit("unexpected location keys")
if location["path"] != "docs/decisions/0001-no-public-bucket-acl.md":
    raise SystemExit("path is %s" % location["path"])
if location["lines"] != {"begin": 1}:
    raise SystemExit("line is %s" % location["lines"])
if not item["fingerprint"] or not item["description"] or not item["check_name"]:
    raise SystemExit("a code quality field is empty")
PY
}

expect_empty() {
  python3 - "$1" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
if doc != []:
    raise SystemExit("a passing plan wrote findings")
PY
}

extract_heredoc() {
  python3 - "$1" "$2" "$3" <<'PY'
import pathlib
import sys

file, marker, dest = sys.argv[1:]
lines = pathlib.Path(file).read_text(encoding="utf-8").splitlines()
start = None
for index, line in enumerate(lines):
    if line.endswith("<<'" + marker + "'"):
        start = index + 1
        break
if start is None:
    raise SystemExit("missing " + marker)
end = None
indent = None
for index in range(start, len(lines)):
    stripped = lines[index].lstrip(" ")
    if stripped == marker:
        end = index
        indent = len(lines[index]) - len(stripped)
        break
if end is None:
    raise SystemExit("unclosed " + marker)
body = []
for line in lines[start:end]:
    if line == "":
        body.append("")
        continue
    if not line.startswith(" " * indent):
        raise SystemExit("bad indent for " + marker)
    body.append(line[indent:])
pathlib.Path(dest).write_text("\n".join(body) + "\n", encoding="utf-8")
PY
}

echo "embedded files"
template="${pack}/templates/check.yml"
extract_heredoc "$template" IPSO_CHECK "${base}/embedded-check.sh"
extract_heredoc "$template" IPSO_INSTALL "${base}/embedded-install.sh"
extract_heredoc "$template" IPSO_CHECKSUMS "${base}/embedded-checksums.txt"
cmp -s "${pack}/check.sh" "${base}/embedded-check.sh" || fail "check.sh drifted from the component"
cmp -s "${pack}/install.sh" "${base}/embedded-install.sh" || fail "install.sh drifted from the component"
cmp -s "${pack}/checksums.txt" "${base}/embedded-checksums.txt" || fail "checksums.txt drifted from the component"

echo "component script runs after the YAML indent is removed"
python3 - "$template" "${base}/component.sh" <<'PY'
import pathlib
import sys

source, dest = sys.argv[1:]
lines = pathlib.Path(source).read_text(encoding="utf-8").splitlines()
start = None
for index, line in enumerate(lines):
    if line.strip() == "- |" and index > 0 and lines[index - 1].strip() == "script:":
        start = index + 1
        break
if start is None:
    raise SystemExit("missing script block")
block = []
indent = None
for line in lines[start:]:
    if line.strip() == "":
        block.append("")
        continue
    spaces = len(line) - len(line.lstrip(" "))
    if indent is None:
        indent = spaces
    if spaces < indent:
        break
    block.append(line[indent:])
text = "\n".join(block) + "\n"
if 'bash "${dir}/check.sh"\n' not in text:
    raise SystemExit("the component script was truncated")
if "\nimport json\n" not in text:
    raise SystemExit("the embedded python is not at column 0")
pathlib.Path(dest).write_text(text, encoding="utf-8")
PY
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${base}/component.sh"
[[ "$status" -eq 0 ]] || fail "the component script failed a clean plan: $(cat "$stderr")"
expect_empty ipso-evidence/gl-code-quality.json
cd "$root"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/public.json" bash "${base}/component.sh"
[[ "$status" -ne 0 ]] || fail "the component script passed a violating plan"
expect_blocker ipso-evidence/gl-code-quality.json
cd "$root"
outside="${base}/outside.yml"
python3 - "$template" "$outside" <<'PY'
import pathlib
import sys

source, dest = sys.argv[1:]
lines = pathlib.Path(source).read_text(encoding="utf-8").splitlines()
markers = ("IPSO_CHECK", "IPSO_INSTALL", "IPSO_CHECKSUMS")
skip = False
closers = {marker: False for marker in markers}
kept = []
for line in lines:
    stripped = line.lstrip(" ")
    if any(line.endswith("<<'" + marker + "'") for marker in markers):
        skip = True
        kept.append(line)
        continue
    if skip and stripped in markers:
        skip = False
        closers[stripped] = True
        kept.append(line)
        continue
    if not skip:
        kept.append(line)
if not all(closers.values()):
    raise SystemExit("a heredoc did not close")
pathlib.Path(dest).write_text("\n".join(kept) + "\n", encoding="utf-8")
PY
grep -q 'codequality: ipso-evidence/gl-code-quality.json' "$outside" || fail "the component does not publish code quality"
grep -q 'expand: false' "$outside" || fail "an input expands in the shell"
if grep -q 'sarif:' "$outside"; then
  fail "the component publishes a SARIF report"
fi
if grep -q 'allow_failure:' "$outside"; then
  fail "the component allows the job to fail"
fi
if grep -q 'CI_JOB_TOKEN' "$outside"; then
  fail "the component reads CI_JOB_TOKEN outside the script"
fi

# A binary that records it was executed.
marker="${base}/ran"
cat >"${base}/touchbin" <<EOF
#!/bin/sh
: > '${marker}'
exit 0
EOF
chmod 0755 "${base}/touchbin"

# Records a GitLab token if the script left one in the environment, then runs the real CLI.
cat >"${base}/envcheck" <<EOF
#!/bin/sh
leak='${base}/leak'
for name in CI_JOB_TOKEN GITLAB_TOKEN PRIVATE_TOKEN CI_REGISTRY_USER CI_REGISTRY_PASSWORD CI_DEPENDENCY_PROXY_USER CI_DEPENDENCY_PROXY_PASSWORD CI_DEPLOY_USER CI_DEPLOY_PASSWORD CI_JOB_JWT CI_JOB_JWT_V2 CI_REPOSITORY_URL DOCKER_AUTH_CONFIG; do
  eval "val=\\\${\$name-}"
  if [ -n "\$val" ]; then
    printf '%s\n' "\$name" >> "\$leak"
  fi
done
exec '${IPSO_BIN}' "\$@"
EOF
chmod 0755 "${base}/envcheck"

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
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/public.json" bash "${pack}/check.sh"
[[ "$status" -ne 0 ]] || fail "a violating plan passed"
fail_code="$status"
[[ -f ipso-evidence/report.json && -f ipso-evidence/ipso.sarif && -f ipso-evidence/gl-code-quality.json ]] || fail "a violating plan wrote no evidence"
refuse_address ipso-evidence
expect_result ipso-evidence/report.json fail
expect_blocker ipso-evidence/gl-code-quality.json
cd "$root"

echo "passing plan"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "a clean plan failed: $(cat "$stderr")"
[[ -f ipso-evidence/report.json && -f ipso-evidence/ipso.sarif && -f ipso-evidence/gl-code-quality.json ]] || fail "a clean plan wrote no evidence"
refuse_address ipso-evidence
expect_result ipso-evidence/report.json pass
expect_empty ipso-evidence/gl-code-quality.json
cd "$root"

echo "tokens stay unset"
rm -f "${base}/leak"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH \
  CI_JOB_TOKEN=job GITLAB_TOKEN=gl PRIVATE_TOKEN=pat \
  CI_REGISTRY_USER=reguser CI_REGISTRY_PASSWORD=reg \
  CI_DEPENDENCY_PROXY_USER=proxyuser CI_DEPENDENCY_PROXY_PASSWORD=proxypass \
  CI_DEPLOY_USER=deployuser CI_DEPLOY_PASSWORD=deploypass \
  CI_JOB_JWT=jwt CI_JOB_JWT_V2=jwt2 \
  CI_REPOSITORY_URL='https://gitlab-ci-token:job@gitlab.example/group/project.git' \
  DOCKER_AUTH_CONFIG='{"auths":{"registry.example":{"password":"docksecret"}}}' \
  IPSO_CLI_PATH="${base}/envcheck" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" \
  bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "a token check failed: $(cat "$stderr")"
[[ ! -s "${base}/leak" ]] || fail "a token reached ipso: $(cat "${base}/leak")"
cd "$root"

echo "git remote loses the job token"
fresh
enter
mkdir -p .git
printf '%s\n' '[remote "origin"]' '	url = https://gitlab-ci-token:supersecret@gitlab.example/group/project.git' >.git/config
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "a git remote scrub failed: $(cat "$stderr")"
if grep -q supersecret .git/config "$stdout" "$stderr"; then
  fail "the job token remained"
fi
grep -F 'url = https://gitlab.example/group/project.git' .git/config >/dev/null || fail "the remote lost its host"
cd "$root"

echo "git remote loses other https credentials"
fresh
enter
mkdir -p .git
printf '%s\n' '[remote "origin"]' '	url = https://oauth2:othersecret@gitlab.example/group/project.git' >.git/config
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "an oauth remote scrub failed: $(cat "$stderr")"
if grep -q othersecret .git/config "$stdout" "$stderr"; then
  fail "the oauth credential remained"
fi
grep -F 'url = https://gitlab.example/group/project.git' .git/config >/dev/null || fail "the oauth remote lost its host"
cd "$root"

echo "submodule remote loses the job token"
fresh
enter
mkdir -p .git/modules/vendor
printf '%s\n' '[remote "origin"]' '	url = https://gitlab-ci-token:modsecret@gitlab.example/group/vendor.git' >.git/modules/vendor/config
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "a submodule remote scrub failed: $(cat "$stderr")"
if grep -q modsecret .git/modules/vendor/config "$stdout" "$stderr"; then
  fail "the submodule token remained"
fi
grep -F 'url = https://gitlab.example/group/vendor.git' .git/modules/vendor/config >/dev/null || fail "the submodule remote lost its host"
cd "$root"

echo "git extraheader loses the job token"
fresh
enter
mkdir -p .git
printf '%s\n' '[http "https://gitlab.example"]' '	extraHeader = Authorization: Basic bW9kc2VjcmV0' >.git/config
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "an extraheader scrub failed: $(cat "$stderr")"
if grep -Ei 'bW9kc2VjcmV0|extraheader|Authorization:' .git/config "$stdout" "$stderr"; then
  fail "the extraheader credential remained"
fi
cd "$root"

echo "git config symlink is refused"
fresh
enter
mkdir -p .git "${base}/git-target"
printf '%s\n' keep >"${base}/git-target/keep"
ln -s "${base}/git-target/keep" .git/config
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "a git config symlink exited ${status}"
grep -F 'a git config must not be a symlink' "$stderr" >/dev/null || fail "a git config symlink gave no reason"
[[ "$(cat "${base}/git-target/keep")" == keep ]] || fail "a git config symlink was written through"
[[ -L .git/config ]] || fail "a git config symlink was replaced"
cd "$root"

echo "evidence symlink is replaced"
fresh
enter
mkdir -p "${base}/evidence-target"
printf '%s\n' keep >"${base}/evidence-target/keep"
ln -s "${base}/evidence-target" ipso-evidence
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 0 ]] || fail "an evidence symlink exited ${status}: $(cat "$stderr")"
[[ ! -L ipso-evidence && -d ipso-evidence ]] || fail "an evidence symlink was followed"
[[ -f ipso-evidence/gl-code-quality.json ]] || fail "an evidence symlink wrote no report"
[[ -f "${base}/evidence-target/keep" ]] || fail "an evidence symlink deleted its target"
[[ ! -e "${base}/evidence-target/report.json" && ! -e "${base}/evidence-target/ipso.sarif" && ! -e "${base}/evidence-target/gl-code-quality.json" ]] || fail "an evidence symlink was written through"
cd "$root"

echo "compile failure publishes an empty code quality report"
cat >"${base}/failcompile" <<'EOF'
#!/bin/sh
if [ "$1" = compile ]; then
  exit 1
fi
if [ "$1" = check ] && [ -z "${2:-}" ]; then
  exit 0
fi
echo ran-engine
exit 0
EOF
chmod 0755 "${base}/failcompile"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/failcompile" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" bash "${pack}/check.sh"
[[ "$status" -eq 1 ]] || fail "a compile failure exited ${status}"
if grep -F 'ran-engine' "$stdout" "$stderr"; then
  fail "a compile failure ran the engine"
fi
[[ ! -f ipso-evidence/ipso.sarif ]] || fail "a compile failure wrote SARIF"
python3 - "${work}/ipso-evidence/gl-code-quality.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
if doc != []:
    raise SystemExit("expected an empty code quality report")
PY
cd "$root"

echo "pinned release refuses a later command"
version_marker="${base}/later-command"
rm -f "$version_marker" "$marker"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${base}/bin:${PATH}" CURL_MARKER="${version_marker}" IPSO_TEMP="${base}" IPSO_COMMAND=snyk bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "a later command exited ${status}"
[[ ! -e "$version_marker" && ! -e "$marker" ]] || fail "a later command downloaded or ran"
grep -F 'that command is not in the pinned release' "$stderr" >/dev/null || fail "a later command gave no reason"
cd "$root"

echo "stale evidence is not republished"
fresh
enter
mkdir -p ipso-evidence
printf '%s\n' 'STALE_MARKER' >ipso-evidence/ipso.sarif
printf '%s\n' 'STALE_MARKER' >ipso-evidence/gl-code-quality.json
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan IPSO_ARGS="plans/public.json" bash "${pack}/check.sh"
[[ "$status" -ne 0 ]] || fail "a failing binary passed"
if grep -R -q STALE_MARKER ipso-evidence 2>/dev/null; then
  fail "a stale evidence file was kept"
fi
python3 - ipso-evidence/gl-code-quality.json <<'PY'
import json
import sys
if json.load(open(sys.argv[1])) != []:
    raise SystemExit("expected an empty code quality report")
PY
cd "$root"

echo "unknown command"
rm -f "$marker"
fresh
enter
mkdir -p ipso-evidence
printf '%s\n' 'STALE_MARKER' >ipso-evidence/gl-code-quality.json
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND='plan; touch pwned' bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "an unknown command exited ${status}"
[[ ! -e "$marker" && ! -e "${work}/pwned" ]] || fail "an unknown command ran"
if grep -R -q STALE_MARKER ipso-evidence 2>/dev/null; then
  fail "an unknown command republished evidence"
fi
python3 - ipso-evidence/gl-code-quality.json <<'PY'
import json
import sys
if json.load(open(sys.argv[1])) != []:
    raise SystemExit("expected an empty code quality report")
PY
cd "$root"

echo "owned flag"
rm -f "$marker"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan IPSO_ARGS='plans/public.json --sarif elsewhere.sarif' bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "an owned flag exited ${status}"
[[ ! -e "$marker" && ! -e "${work}/elsewhere.sarif" ]] || fail "an owned flag ran"
cd "$root"

echo "blank args"
rm -f "$marker"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan IPSO_ARGS='   ' bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "blank args exited ${status}"
grep -F 'args is empty' "$stderr" >/dev/null || fail "blank args gave no reason"
[[ ! -e "$marker" ]] || fail "blank args ran the binary"
cd "$root"

echo "args length"
fresh
enter
long="$(printf 'a%.0s' {1..513})"
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="$long" bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "a long args list exited ${status}"
grep -F 'args is too long' "$stderr" >/dev/null || fail "a long args list gave no length error"
if grep -F 'forbidden character' "$stderr" >/dev/null; then
  fail "a long args list was called a forbidden character"
fi
cd "$root"

echo "command substitution"
fresh
enter
# The substitutions must stay rejected. The script must not run them.
# shellcheck disable=SC2016
literal='$(touch pwned) `touch pwned`'
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="$literal" bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "command substitution exited ${status}"
[[ ! -e "${work}/pwned" ]] || fail "command substitution ran"
cd "$root"

echo "windows arch"
rm -f "$marker"
fresh
enter
run env CI_RUNNER_EXECUTABLE_ARCH=windows/amd64 IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "Windows arch exited ${status}"
[[ ! -e "$marker" ]] || fail "Windows arch ran the binary"
grep -F 'ipso check runs on Linux and macOS runners' "$stderr" >/dev/null || fail "Windows arch gave no reason"
cd "$root"

echo "windows uname"
rm -f "$marker"
fresh
enter
mkdir -p "${base}/fake"
cat >"${base}/fake/uname" <<'EOF'
#!/bin/sh
echo MINGW64_NT
EOF
chmod 0755 "${base}/fake/uname"
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${base}/fake:${PATH}" IPSO_CLI_PATH="${base}/touchbin" IPSO_COMMAND=plan bash "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "Windows uname exited ${status}"
[[ ! -e "$marker" ]] || fail "Windows uname ran the binary"
cd "$root"

echo "missing python3"
nopy="${base}/nopy"
mkdir -p "$nopy"
for tool in uname mkdir mktemp chmod cat dirname rm; do
  source_tool="$(command -v "$tool")"
  [[ "$source_tool" == /* ]] || fail "no path for ${tool}"
  ln -s "$source_tool" "${nopy}/${tool}"
done
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${nopy}" IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/private.json" "$(command -v bash)" "${pack}/check.sh"
[[ "$status" -eq 2 ]] || fail "a missing python3 exited ${status}: $(cat "$stderr")"
grep -F 'python3 is not installed' "$stderr" >/dev/null || fail "a missing python3 gave no reason"
[[ ! -f ipso-evidence/gl-code-quality.json ]] || fail "a missing python3 wrote a code quality report"
cd "$root"

echo "failed check keeps its exit code without python3"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${nopy}" IPSO_CLI_PATH="${IPSO_BIN}" IPSO_COMMAND=plan IPSO_ARGS="plans/public.json" "$(command -v bash)" "${pack}/check.sh"
[[ "$status" -eq "$fail_code" ]] || fail "a missing python3 masked the check exit: got ${status} want ${fail_code}"
python3 - ipso-evidence/gl-code-quality.json <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
if doc != [{
    "description": "ipso could not write the code quality report",
    "check_name": "ipso/code-quality",
    "fingerprint": "ipso-code-quality",
    "severity": "blocker",
    "location": {"path": "ipso-evidence/ipso.sarif", "lines": {"begin": 1}},
}]:
    raise SystemExit("expected the conversion fallback")
PY
if grep -q aws_s3_bucket ipso-evidence/gl-code-quality.json; then
  fail "a resource address reached the conversion fallback"
fi
cd "$root"

echo "bad version"
version_marker="${base}/curled"
rm -f "$version_marker"
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${base}/bin:${PATH}" CURL_MARKER="${version_marker}" IPSO_TEMP="${base}" IPSO_VERSION=9.9.9 bash "${pack}/install.sh"
[[ "$status" -eq 2 ]] || fail "a different version exited ${status}"
[[ ! -e "$version_marker" ]] || fail "a different version downloaded"

echo "bad hash"
install_root="${base}/installs"
mkdir -p "$install_root"
run env -u CI_RUNNER_EXECUTABLE_ARCH PATH="${base}/bin:${PATH}" IPSO_TEMP="${install_root}" IPSO_VERSION=0.4.0 bash "${pack}/install.sh"
[[ "$status" -eq 2 ]] || fail "a bad hash exited ${status}"
if find "$install_root" -name ipso -type f | grep -q .; then
  fail "a bad hash left a binary"
fi
grep -F 'the archive hash does not match the pin' "$stderr" >/dev/null || fail "a bad hash gave no reason"

echo "bundle skips compile"
: >"${base}/argv"
fresh
enter
run env -u CI_RUNNER_EXECUTABLE_ARCH IPSO_CLI_PATH="${base}/record" IPSO_COMMAND=plan IPSO_ARGS='--bundle layout' bash "${pack}/check.sh"
if grep -q '^compile$' "${base}/argv"; then
  fail "compile ran for a bundle"
fi
grep -q '^check$' "${base}/argv" || fail "the bundle path did not check"
cd "$root"

echo "ok"
