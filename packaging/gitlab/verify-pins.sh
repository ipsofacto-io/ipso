#!/usr/bin/env bash
# Downloads the four pinned ipso 0.4.0 archives, checks each attestation, and checks the
# sha256 lines shipped with the component. CI runs this on a same-repository build.
set -euo pipefail

fail() {
  echo "ipso: $1" >&2
  exit 1
}

command -v gh >/dev/null 2>&1 || fail "gh is not installed"
here="$(cd "$(dirname "$0")" && pwd)"
checksums="${here}/checksums.txt"
dest="$(mktemp -d)"
version="0.4.0"

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    fail "a sha256 tool is not installed"
  fi
}

count=0
while read -r hash name; do
  [[ "$name" == ipso_${version}_*.tar.gz ]] || fail "the checksum file has an unexpected archive"
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail "the checksum file has a bad hash"
  count=$((count + 1))
  echo "verify ${name}"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    --output "${dest}/${name}" \
    "https://github.com/ipsofacto-io/ipso/releases/download/v${version}/${name}"
  gh attestation verify "${dest}/${name}" \
    --repo ipsofacto-io/ipso \
    --signer-workflow ipsofacto-io/.github/.github/workflows/release-cli.yml \
    --source-ref "refs/tags/v${version}" >/dev/null
  actual="$(hash_of "${dest}/${name}")"
  [[ "$actual" == "$hash" ]] || fail "the archive hash does not match the pin"
done <"$checksums"
[[ "$count" -eq 4 ]] || fail "the checksum file must list four archives"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    tar --extract --gzip --file "${dest}/ipso_${version}_linux_amd64.tar.gz" --directory "$dest" ipso
    version_line="$("${dest}/ipso" version)"
    [[ "$version_line" == "ipso ${version} "* ]] || fail "the pinned binary is not ipso ${version}"
    ;;
esac

echo "pins ok"
