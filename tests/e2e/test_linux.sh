#!/usr/bin/env bash
# Linux E2E tests for mori

set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build --release

BIN="sudo ./target/release/mori"

# Test 1: Network is blocked without --allow-network
output=$($BIN -- curl --max-time 2 -I https://example.com 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Network should be blocked without --allow-network"
    exit 1
fi

# Test 2: Allowed domain can communicate
output=$($BIN --allow-network "example.com" -- curl --max-time 2 -I https://example.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Allowed domain should be accessible"
    exit 1
fi

# Test 3: Non-allowed domain is blocked
output=$($BIN --allow-network "example.com" -- curl --max-time 2 -I https://google.com 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Non-allowed domain should be blocked"
    exit 1
fi

# Test 4: Multiple entries - allowed domains work
output=$($BIN --allow-network "example.com,google.com" -- curl --max-time 2 -I https://example.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: First allowed domain should be accessible"
    exit 1
fi

output=$($BIN --allow-network "example.com,google.com" -- curl --max-time 2 -I https://google.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Second allowed domain should be accessible"
    exit 1
fi

# Test 5: IP address allowlist works
output=$($BIN --allow-network "93.184.215.14" -- curl --max-time 2 -I http://93.184.215.14 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL: Allowed IP should be accessible"
    exit 1
fi

# Test 6: Domain with port
$BIN --allow-network "example.com:443" -- echo "test" &>/dev/null

echo "All tests passed!"
