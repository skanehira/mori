#!/usr/bin/env bash
# Linux E2E tests for mori

set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build --release

BIN="sudo ./target/release/mori"

echo "Testing network access control..."

# Test 1: Network is blocked without --allow-network
echo "[Test 1] Network is blocked without --allow-network"
echo "  [1-1] Testing: curl to example.com should be blocked"
output=$($BIN -- curl --max-time 5 -I https://example.com 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [1-1]: Network should be blocked without --allow-network"
    echo "  Command: $BIN -- curl --max-time 5 -I https://example.com"
    echo "  Output: $output"
    exit 1
fi
echo "  [1-1] PASS"

# Test 2: Allowed domain can communicate
echo "[Test 2] Allowed domain can communicate"
echo "  [2-1] Testing: curl to allowed example.com should succeed"
output=$($BIN --allow-network "example.com" -- curl --max-time 5 -I https://example.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [2-1]: Allowed domain should be accessible"
    echo "  Command: $BIN --allow-network example.com -- curl --max-time 5 -I https://example.com"
    echo "  Output: $output"
    exit 1
fi
echo "  [2-1] PASS"

# Test 3: Non-allowed domain is blocked
echo "[Test 3] Non-allowed domain is blocked"
echo "  [3-1] Testing: curl to non-allowed google.com should be blocked"
output=$($BIN --allow-network "example.com" -- curl --max-time 5 -I https://google.com 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [3-1]: Non-allowed domain should be blocked"
    echo "  Command: $BIN --allow-network example.com -- curl --max-time 5 -I https://google.com"
    echo "  Output: $output"
    exit 1
fi
echo "  [3-1] PASS"

# Test 4: Multiple entries - allowed domains work
echo "[Test 4] Multiple entries - allowed domains work"
echo "  [4-1] Testing: curl to first allowed domain (example.com) should succeed"
output=$($BIN --allow-network "example.com,google.com" -- curl --max-time 5 -I https://example.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [4-1]: First allowed domain should be accessible"
    echo "  Command: $BIN --allow-network example.com,google.com -- curl --max-time 5 -I https://example.com"
    echo "  Output: $output"
    exit 1
fi
echo "  [4-1] PASS"

echo "  [4-2] Testing: curl to second allowed domain (google.com) should succeed"
output=$($BIN --allow-network "example.com,google.com" -- curl --max-time 5 -I https://google.com 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [4-2]: Second allowed domain should be accessible"
    echo "  Command: $BIN --allow-network example.com,google.com -- curl --max-time 5 -I https://google.com"
    echo "  Output: $output"
    exit 1
fi
echo "  [4-2] PASS"

# Test 5: IP address allowlist works
echo "[Test 5] IP address allowlist works"
echo "  [5-1] Testing: curl to allowed IP address should succeed"
output=$($BIN --allow-network "23.192.228.80" -- curl --max-time 5 -I -H "Host: example.com" http://23.192.228.80 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [5-1]: Allowed IP should be accessible"
    echo "  Command: $BIN --allow-network 23.192.228.80 -- curl --max-time 5 -I -H \"Host: example.com\" http://23.192.228.80"
    echo "  Output: $output"
    exit 1
fi
echo "  [5-1] PASS"

# Test 6: Domain with port
echo "[Test 6] Domain with port"
echo "  [6-1] Testing: domain with port specification should work"
if ! $BIN --allow-network "example.com:443" -- echo "test" &>/dev/null; then
    echo "FAIL [6-1]: Domain with port should work"
    echo "  Command: $BIN --allow-network example.com:443 -- echo test"
    exit 1
fi
echo "  [6-1] PASS"

# Test 7: CIDR range allowlist works
echo "[Test 7] CIDR range allowlist works"
echo "  [7-1] Testing: curl to IP within allowed CIDR range should succeed"
# Use /24 CIDR which allows 256 addresses (23.192.228.0 - 23.192.228.255)
output=$($BIN --allow-network "23.192.228.0/24" -- curl --max-time 5 -I -H "Host: example.com" http://23.192.228.80 2>&1)
if ! echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [7-1]: IP within allowed CIDR range should be accessible"
    echo "  Command: $BIN --allow-network 23.192.228.0/24 -- curl --max-time 5 -I -H \"Host: example.com\" http://23.192.228.80"
    echo "  Output: $output"
    exit 1
fi
echo "  [7-1] PASS"

echo "  [7-2] Testing: curl to IP outside allowed CIDR range should be blocked"
# 23.220.75.232 is outside the /24 range (23.192.228.0/24)
output=$($BIN --allow-network "23.192.228.0/24" -- curl --max-time 5 -I -H "Host: example.com" http://23.220.75.232 2>&1 || true)
if echo "$output" | grep -qiE "^HTTP/[0-9.]+ (200|301|302)"; then
    echo "FAIL [7-2]: IP outside allowed CIDR range should be blocked"
    echo "  Command: $BIN --allow-network 23.192.228.0/24 -- curl --max-time 5 -I -H \"Host: example.com\" http://23.220.75.232"
    echo "  Output: $output"
    exit 1
fi
echo "  [7-2] PASS"

echo ""
echo "All network access control tests passed!"
