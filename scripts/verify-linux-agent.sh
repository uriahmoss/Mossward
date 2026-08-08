#!/bin/sh
set -eu

artifact=${1:-}
bundle=${2:-}
public_key=${3:-}

if [ -z "$artifact" ] || [ -z "$bundle" ] || [ -z "$public_key" ]; then
	echo "usage: verify-linux-agent.sh ARTIFACT SIGSTORE_BUNDLE PUBLIC_KEY" >&2
	exit 2
fi
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }
cosign verify-blob --key "$public_key" --bundle "$bundle" "$artifact"
