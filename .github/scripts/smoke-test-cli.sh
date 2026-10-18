#!/usr/bin/env bash
# Smoke-tests a published CLI binary against the real Bun release signature.
# Usage: smoke-test-cli.sh <path-to-scarlet-openpgp>
set -euo pipefail

cli="$1"
assets=tests/Scarlet.OpenPgp.Tests/TestAssets/bun-release
mkdir -p out

echo "== 1. Genuine signature: must verify and output exactly the signed text"
"$cli" verify --key "$assets/bun-public-key.asc" --signature "$assets/SHASUMS256.txt.asc" --output out/signed.txt
diff <(tr -d '\r' < out/signed.txt) <(tr -d '\r' < "$assets/SHASUMS256.txt")

# Unsigned text injected before the clearsigned block must be rejected as malformed (exit 65).
echo "== 2. Tampered copy (unsigned hash line injected above the signed block): the failure below is expected"
{ echo "deadbeef  bun-linux-x64.zip"; cat "$assets/SHASUMS256.txt.asc"; } > out/tampered.asc
set +e
"$cli" verify --key "$assets/bun-public-key.asc" --signature out/tampered.asc
code=$?
set -e
if [ "$code" -ne 65 ]; then
  echo "Expected exit code 65 for a tampered message, got $code"
  exit 1
fi
echo "== Tampered copy rejected with exit code 65, as required"
