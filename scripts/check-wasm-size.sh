#!/usr/bin/env bash
# Fail if a wasm artifact exceeds its byte budget.
#
# Usage: scripts/check-wasm-size.sh <file> <max-bytes>
# Silent on success (the Makefile prints the size). Wired into `make wasm`,
# which `make ci` runs.

set -euo pipefail

file="${1:?usage: check-wasm-size.sh <file> <max-bytes>}"
max="${2:?usage: check-wasm-size.sh <file> <max-bytes>}"

if [[ ! "$max" =~ ^[0-9]+$ ]]; then
  echo "check-wasm-size: <max-bytes> must be a non-negative integer, got '$max' — usage: check-wasm-size.sh <file> <max-bytes>" >&2
  exit 2
fi

if [[ ! -f "$file" ]]; then
  echo "check-wasm-size: $file not found — remediation: run make wasm" >&2
  exit 2
fi

size=$(wc -c <"$file" | tr -d ' ')
if (( size > max )); then
  echo "check-wasm-size: $file is $size bytes, over the $max-byte budget — remediation: find the heavy import with 'GOOS=js GOARCH=wasm go list -deps ./cmd/wardwasm' (internal/config, crypto/x509 and net are the usual culprits); TinyGo is the spec's last resort" >&2
  exit 1
fi
