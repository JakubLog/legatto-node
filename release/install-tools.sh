#!/usr/bin/env bash
# Install the pinned tools of release/build.sh on a linux/amd64 CI runner: syft and yq.
#
# Same versions and sha256 as the vendor's tool set (legatto-infra
# tools/install.sh), so the CI reference build and the vendor's build produce
# the same SBOMs. Every download is checked against the sha256 below.
#
# Usage: release/install-tools.sh [--prefix DIR]   (binaries go to DIR/bin, default /usr/local)
# Exit: 0 installed, 1 download or checksum failure, 2 bad arguments, 4 wrong platform.
set -euo pipefail

prefix=/usr/local
while (($#)); do
	case "$1" in
	--prefix) prefix="${2:?--prefix needs a directory}"; shift 2 ;;
	*) echo "install-tools.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done
if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
	echo "install-tools.sh: pins are for linux/amd64 only (got $(uname -s)/$(uname -m))" >&2
	exit 4
fi

# name|version|url|sha256|kind (raw: the download is the binary; tgz: extract <name>)
pins=(
	"syft|1.57.2|https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_linux_amd64.tar.gz|ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b|tgz"
	"yq|4.54.3|https://github.com/mikefarah/yq/releases/download/v4.54.3/yq_linux_amd64|129534601871538efe0ba4c5e62a34fb1d5f469bcb975c4fddeb467d82974973|raw"
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$prefix/bin"
for pin in "${pins[@]}"; do
	IFS='|' read -r name version url sha256 kind <<<"$pin"
	dl="$work/$name.download"
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dl" "$url"
	got="$(sha256sum "$dl" | cut -d' ' -f1)"
	if [[ "$got" != "$sha256" ]]; then
		echo "install-tools.sh: sha256 mismatch for $name $version: expected $sha256, got $got" >&2
		exit 1
	fi
	if [[ "$kind" == tgz ]]; then
		tar -xzf "$dl" -C "$work" "$name"
		install -m 0755 "$work/$name" "$prefix/bin/$name"
	else
		install -m 0755 "$dl" "$prefix/bin/$name"
	fi
	echo "installed $name $version"
done
