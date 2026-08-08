#!/bin/sh
set -eu

version=${1:-}
architecture=${2:-amd64}
output_directory=${3:-dist}

if [ -z "$version" ]; then
	echo "usage: package-linux-agent.sh VERSION [amd64|arm64] [OUTPUT_DIRECTORY]" >&2
	exit 2
fi
case "$architecture" in
	amd64|arm64) ;;
	*) echo "unsupported Linux architecture: $architecture" >&2; exit 2 ;;
esac
if [ -z "${MOSSWARD_COSIGN_KEY:-}" ]; then
	echo "MOSSWARD_COSIGN_KEY must identify an external Cosign key or KMS URI" >&2
	exit 1
fi
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }

artifact="mossward-agent_${version}_linux_${architecture}.tar.gz"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
mkdir -p "$output_directory" "$staging/mossward-agent"

CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -ldflags='-s -w -buildid=' -o "$staging/mossward-agent/mossward-agent" ./cmd/mossward-agent
cp deploy/linux/mossward-agent.service "$staging/mossward-agent/"
cp deploy/linux/install-mossward-agent.sh "$staging/mossward-agent/"
cp config/mossward-agent.json.example "$staging/mossward-agent/agent.json.example"
cp docs/ENDPOINT_AGENT.md "$staging/mossward-agent/README.md"
tar -C "$staging" -czf "$output_directory/$artifact" mossward-agent

cosign sign-blob --yes --key "$MOSSWARD_COSIGN_KEY" --bundle "$output_directory/$artifact.sigstore.json" "$output_directory/$artifact"
echo "created signed release: $output_directory/$artifact"
