#!/usr/bin/env bash
# macOS E2E tests for mori

set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build --release

BIN="./target/release/mori"

# Test 1: Network is blocked without --allow-network-all
output=$($BIN -- curl --max-time 2 -I https://example.com 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Network should be blocked without --allow-network-all"
    exit 1
fi

# Test 2: Network is allowed with --allow-network-all
output=$($BIN --allow-network-all -- curl --max-time 2 -I https://example.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Network should be allowed with --allow-network-all"
    exit 1
fi

echo "All tests passed!"
