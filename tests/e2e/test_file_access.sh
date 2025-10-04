#!/usr/bin/env bash
# E2E tests for mori file access control

set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build --release

BIN="./target/release/mori"
if [[ "$(uname)" == "Linux" ]]; then
    BIN="sudo ./target/release/mori"
fi

# Use project-local tmp directory instead of system /tmp
# because macOS system.sb always allows /tmp
TEMP_DIR="$(pwd)/tmp/test-$$"
mkdir -p "$TEMP_DIR"

# Cleanup function to ensure tmp directory is removed
cleanup() {
    rm -rf "$TEMP_DIR"
    # Remove tmp directory if empty
    rmdir "$(pwd)/tmp" 2>/dev/null || true
}
trap cleanup EXIT

echo "Testing file access control..."

# Test 1: --deny-file-read blocks reading but allows writing
echo "[Test 1] --deny-file-read blocks reading but allows writing"
TEST_FILE="$TEMP_DIR/test_read.txt"
echo "initial content" > "$TEST_FILE"

# Should fail to read
echo "  [1-1] Testing: cat (read) on read-denied file should fail"
if $BIN --deny-file-read "$TEST_FILE" -- cat "$TEST_FILE" > /dev/null 2>&1; then
    echo "FAIL [1-1]: Reading denied file should fail"
    echo "  Command: $BIN --deny-file-read $TEST_FILE -- cat $TEST_FILE"
    exit 1
fi
echo "  [1-1] PASS"

# Should succeed to write
echo "  [1-2] Testing: write on read-denied file should succeed"
$BIN --deny-file-read "$TEST_FILE" -- sh -c "echo 'new content' > $TEST_FILE"
if ! grep -q "new content" "$TEST_FILE"; then
    echo "FAIL [1-2]: Writing to read-denied file should succeed"
    echo "  Command: $BIN --deny-file-read $TEST_FILE -- sh -c \"echo 'new content' > $TEST_FILE\""
    exit 1
fi
echo "  [1-2] PASS"

# Test 2: --deny-file-write blocks writing but allows reading
echo "[Test 2] --deny-file-write blocks writing but allows reading"
TEST_FILE2="$TEMP_DIR/test_write.txt"
echo "original" > "$TEST_FILE2"

# Should fail to write
echo "  [2-1] Testing: write on write-denied file should fail"
if $BIN --deny-file-write "$TEST_FILE2" -- sh -c "echo 'modified' > $TEST_FILE2" > /dev/null 2>&1; then
    echo "FAIL [2-1]: Writing to write-denied file should fail"
    echo "  Command: $BIN --deny-file-write $TEST_FILE2 -- sh -c \"echo 'modified' > $TEST_FILE2\""
    exit 1
fi
echo "  [2-1] PASS"

# Content should remain unchanged
echo "  [2-2] Testing: content should remain unchanged after failed write"
if ! grep -q "original" "$TEST_FILE2"; then
    echo "FAIL [2-2]: Content should remain unchanged after failed write"
    echo "  Expected: 'original', Got: $(cat $TEST_FILE2)"
    exit 1
fi
echo "  [2-2] PASS"

# Should succeed to read
echo "  [2-3] Testing: read on write-denied file should succeed"
output=$($BIN --deny-file-write "$TEST_FILE2" -- cat "$TEST_FILE2")
if ! echo "$output" | grep -q "original"; then
    echo "FAIL [2-3]: Reading write-denied file should succeed"
    echo "  Command: $BIN --deny-file-write $TEST_FILE2 -- cat $TEST_FILE2"
    echo "  Output: $output"
    exit 1
fi
echo "  [2-3] PASS"

# Test 3: --deny-file blocks both reading and writing
echo "[Test 3] --deny-file blocks both reading and writing"
TEST_FILE3="$TEMP_DIR/test_both.txt"
echo "test content" > "$TEST_FILE3"

# Should fail to read
echo "  [3-1] Testing: read on fully denied file should fail"
if $BIN --deny-file "$TEST_FILE3" -- cat "$TEST_FILE3" > /dev/null 2>&1; then
    echo "FAIL [3-1]: Reading fully denied file should fail"
    echo "  Command: $BIN --deny-file $TEST_FILE3 -- cat $TEST_FILE3"
    exit 1
fi
echo "  [3-1] PASS"

# Should fail to write
echo "  [3-2] Testing: write on fully denied file should fail"
if $BIN --deny-file "$TEST_FILE3" -- sh -c "echo 'forbidden' > $TEST_FILE3" > /dev/null 2>&1; then
    echo "FAIL [3-2]: Writing to fully denied file should fail"
    echo "  Command: $BIN --deny-file $TEST_FILE3 -- sh -c \"echo 'forbidden' > $TEST_FILE3\""
    exit 1
fi
echo "  [3-2] PASS"

# Test 4: Multiple deny paths with different modes
echo "[Test 4] Multiple deny paths with different modes"
FILE1="$TEMP_DIR/file1.txt"
FILE2="$TEMP_DIR/file2.txt"
FILE3="$TEMP_DIR/file3.txt"
echo "content1" > "$FILE1"
echo "content2" > "$FILE2"
echo "content3" > "$FILE3"

# Deny read on file1, write on file2, both on file3
# This command should fail because it tries to read file1
echo "  [4-1] Testing: multiple deny policies should be enforced"
if $BIN --deny-file-read "$FILE1" --deny-file-write "$FILE2" --deny-file "$FILE3" -- \
    sh -c "cat $FILE1 && echo 'test' > $FILE2 && cat $FILE3" > /dev/null 2>&1; then
    echo "FAIL [4-1]: Multiple deny policies should be enforced"
    echo "  Command: $BIN --deny-file-read $FILE1 --deny-file-write $FILE2 --deny-file $FILE3 -- sh -c \"cat $FILE1 && echo 'test' > $FILE2 && cat $FILE3\""
    exit 1
fi
echo "  [4-1] PASS"

# Test 5: Allowed files should work (deny-list mode)
echo "[Test 5] Allowed files should work (deny-list mode)"
ALLOWED_FILE="$TEMP_DIR/allowed.txt"
DENIED_FILE="$TEMP_DIR/denied.txt"
echo "allowed content" > "$ALLOWED_FILE"
echo "denied content" > "$DENIED_FILE"

# Only deny DENIED_FILE, ALLOWED_FILE should work
echo "  [5-1] Testing: reading allowed file should succeed when other file is denied"
output=$($BIN --deny-file-read "$DENIED_FILE" -- cat "$ALLOWED_FILE")
if ! echo "$output" | grep -q "allowed content"; then
    echo "FAIL [5-1]: Reading allowed file should succeed"
    echo "  Command: $BIN --deny-file-read $DENIED_FILE -- cat $ALLOWED_FILE"
    echo "  Output: $output"
    exit 1
fi
echo "  [5-1] PASS"

# Test 6: Relative path normalization
echo "[Test 6] Relative path normalization"
# This test verifies that relative paths in --deny-file are normalized correctly
# Create a file and deny it using a relative path, then try to access it
RELATIVE_FILE="../relative_test.txt"
echo "relative test" > "$RELATIVE_FILE"

# Deny using relative path
echo "  [6-1] Testing: relative path should be normalized and denied"
if $BIN --deny-file-read "$RELATIVE_FILE" -- cat "$RELATIVE_FILE" > /dev/null 2>&1; then
    echo "FAIL [6-1]: Relative path should be normalized and denied"
    echo "  Command: $BIN --deny-file-read $RELATIVE_FILE -- cat $RELATIVE_FILE"
    rm -f "$RELATIVE_FILE"
    exit 1
fi
echo "  [6-1] PASS"

rm -f "$RELATIVE_FILE"

# Test 7: Append mode should be denied with --deny-file-write
echo "[Test 7] Append mode should be denied with --deny-file-write"
APPEND_FILE="$TEMP_DIR/append.txt"
echo "initial" > "$APPEND_FILE"

echo "  [7-1] Testing: append to write-denied file should fail"
if $BIN --deny-file-write "$APPEND_FILE" -- sh -c "echo 'appended' >> $APPEND_FILE" > /dev/null 2>&1; then
    echo "FAIL [7-1]: Append to write-denied file should fail"
    echo "  Command: $BIN --deny-file-write $APPEND_FILE -- sh -c \"echo 'appended' >> $APPEND_FILE\""
    exit 1
fi
echo "  [7-1] PASS"

# Content should remain unchanged
echo "  [7-2] Testing: content should remain unchanged after failed append"
if ! grep -q "^initial$" "$APPEND_FILE"; then
    echo "FAIL [7-2]: Content should remain unchanged after failed append"
    echo "  Expected: 'initial', Got: $(cat $APPEND_FILE)"
    exit 1
fi
echo "  [7-2] PASS"

# Test 8: No file policy allows all access
echo "[Test 8] No file policy allows all access"
NO_POLICY_FILE="$TEMP_DIR/no_policy.txt"
echo "test" > "$NO_POLICY_FILE"

# Should succeed without any deny flags
echo "  [8-1] Testing: file access should be allowed by default"
output=$($BIN --allow-network-all -- cat "$NO_POLICY_FILE")
if ! echo "$output" | grep -q "test"; then
    echo "FAIL [8-1]: File access should be allowed by default"
    echo "  Command: $BIN --allow-network-all -- cat $NO_POLICY_FILE"
    echo "  Output: $output"
    exit 1
fi
echo "  [8-1] PASS"

echo ""
echo "All file access control tests passed!"
