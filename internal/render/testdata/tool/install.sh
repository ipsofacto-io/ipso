#!/bin/sh
# Download the Helm and Kustomize releases pinned in bin.lock.
set -eu
cd "$(dirname "$0")"
mkdir -p bin

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*)
	echo "unsupported architecture ${arch}" >&2
	exit 1
	;;
esac
case "$os" in
linux | darwin) ;;
*)
	echo "unsupported operating system ${os}" >&2
	exit 1
	;;
esac

check() {
	file="$1"
	want="$2"
	if command -v sha256sum >/dev/null 2>&1; then
		echo "${want}  ${file}" | sha256sum -c -
	else
		echo "${want}  ${file}" | shasum -a 256 -c -
	fi
}

# install <tool> <path of the binary inside the archive>
install_tool() {
	tool="$1"
	inside="$2"
	if [ -x "bin/${tool}" ]; then
		return 0
	fi
	sum=""
	url=""
	while read -r name line_sum line_url; do
		case "$name" in
		"" | \#*) continue ;;
		esac
		case "$name" in
		"${tool}"-*-"$os"-"$arch")
			if [ -n "$url" ]; then
				echo "bin.lock has two ${tool} builds for ${os}/${arch}" >&2
				exit 1
			fi
			sum=$line_sum
			url=$line_url
			;;
		esac
	done < bin.lock
	if [ -z "$url" ]; then
		echo "bin.lock has no ${tool} build for ${os}/${arch}" >&2
		exit 1
	fi
	tmp=$(mktemp -d)
	archive="${tmp}/archive.tar.gz"
	curl -fsSL -o "$archive" "$url"
	check "$archive" "$sum"
	tar -xzf "$archive" -C "$tmp"
	if [ ! -f "${tmp}/${inside}" ]; then
		echo "archive has no ${inside}" >&2
		exit 1
	fi
	mv "${tmp}/${inside}" "bin/${tool}"
	chmod 755 "bin/${tool}"
	rm -rf "$tmp"
}

install_tool helm "${os}-${arch}/helm"
install_tool kustomize kustomize
