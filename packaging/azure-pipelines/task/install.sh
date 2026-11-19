#!/usr/bin/env bash
# Downloads one pinned ipso release and prints its path. The archive is extracted only after
# its sha256 matches the file shipped with this task. Any other version fails before curl runs.
set -euo pipefail

fail() {
  echo "##vso[task.logissue type=error]$1" >&2
  exit 2
}

[[ "${IPSO_TEMP:-}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "IPSO_TEMP is missing or not a safe path"
[[ "${IPSO_VERSION:-}" == "0.4.0" ]] || fail "version must be 0.4.0"

case "${AGENT_OS:-}" in
  Windows_NT) fail "ipso check runs on Linux and macOS agents" ;;
esac
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN* | Windows*) fail "ipso check runs on Linux and macOS agents" ;;
esac

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux_amd64 ;;
  Linux/aarch64) platform=linux_arm64 ;;
  Darwin/x86_64) platform=darwin_amd64 ;;
  Darwin/arm64) platform=darwin_arm64 ;;
  *) fail "ipso check runs on Linux and macOS, on X64 and ARM64" ;;
esac

archive="ipso_${IPSO_VERSION}_${platform}.tar.gz"
here="$(cd "$(dirname "$0")" && pwd)"
expected=""
while read -r hash name; do
  [[ "$name" == "$archive" ]] || continue
  [[ -z "$expected" ]] || fail "the checksum file lists this archive twice"
  expected="$hash"
done <"${here}/checksums.txt"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "the checksum file has no hash for this archive"

directory="$(mktemp -d "${IPSO_TEMP}/ipso-install.XXXXXX")"
cleanup() { rm -rf "$directory"; }
trap cleanup EXIT

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
  --output "${directory}/${archive}" \
  "https://github.com/ipsofacto-io/ipso/releases/download/v${IPSO_VERSION}/${archive}"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${directory}/${archive}" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${directory}/${archive}" | awk '{ print $1 }')"
else
  fail "a sha256 tool is not installed"
fi
[[ "$actual" == "$expected" ]] || fail "the archive hash does not match the pin"

tar --extract --gzip --file "${directory}/${archive}" --directory "$directory" ipso
rm -f "${directory}/${archive}"
chmod 0755 "${directory}/ipso"
trap - EXIT
printf '%s\n' "${directory}/ipso"
