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
TEST_FILE="$TEMP_DIR/test_read.txt"
echo "initial content" > "$TEST_FILE"

# Should fail to read
if $BIN --deny-file-read "$TEST_FILE" -- cat "$TEST_FILE" > /dev/null 2>&1; then
    echo "FAIL: Reading denied file should fail"
    exit 1
fi

# Should succeed to write
$BIN --deny-file-read "$TEST_FILE" -- sh -c "echo 'new content' > $TEST_FILE"
if ! grep -q "new content" "$TEST_FILE"; then
    echo "FAIL: Writing to read-denied file should succeed"
    exit 1
fi

# Test 2: --deny-file-write blocks writing but allows reading
TEST_FILE2="$TEMP_DIR/test_write.txt"
echo "original" > "$TEST_FILE2"

# Should fail to write
if $BIN --deny-file-write "$TEST_FILE2" -- sh -c "echo 'modified' > $TEST_FILE2" > /dev/null 2>&1; then
    echo "FAIL: Writing to write-denied file should fail"
    exit 1
fi

# Content should remain unchanged
if ! grep -q "original" "$TEST_FILE2"; then
    echo "FAIL: Content should remain unchanged after failed write"
    exit 1
fi

# Should succeed to read
output=$($BIN --deny-file-write "$TEST_FILE2" -- cat "$TEST_FILE2")
if ! echo "$output" | grep -q "original"; then
    echo "FAIL: Reading write-denied file should succeed"
    exit 1
fi

# Test 3: --deny-file blocks both reading and writing
TEST_FILE3="$TEMP_DIR/test_both.txt"
echo "test content" > "$TEST_FILE3"

# Should fail to read
if $BIN --deny-file "$TEST_FILE3" -- cat "$TEST_FILE3" > /dev/null 2>&1; then
    echo "FAIL: Reading fully denied file should fail"
    exit 1
fi

# Should fail to write
if $BIN --deny-file "$TEST_FILE3" -- sh -c "echo 'forbidden' > $TEST_FILE3" > /dev/null 2>&1; then
    echo "FAIL: Writing to fully denied file should fail"
    exit 1
fi

# Test 4: Multiple deny paths with different modes
FILE1="$TEMP_DIR/file1.txt"
FILE2="$TEMP_DIR/file2.txt"
FILE3="$TEMP_DIR/file3.txt"
echo "content1" > "$FILE1"
echo "content2" > "$FILE2"
echo "content3" > "$FILE3"

# Deny read on file1, write on file2, both on file3
# This command should fail because it tries to read file1
if $BIN --deny-file-read "$FILE1" --deny-file-write "$FILE2" --deny-file "$FILE3" -- \
    sh -c "cat $FILE1 && echo 'test' > $FILE2 && cat $FILE3" > /dev/null 2>&1; then
    echo "FAIL: Multiple deny policies should be enforced"
    exit 1
fi

# Test 5: Allowed files should work (deny-list mode)
ALLOWED_FILE="$TEMP_DIR/allowed.txt"
DENIED_FILE="$TEMP_DIR/denied.txt"
echo "allowed content" > "$ALLOWED_FILE"
echo "denied content" > "$DENIED_FILE"

# Only deny DENIED_FILE, ALLOWED_FILE should work
output=$($BIN --deny-file-read "$DENIED_FILE" -- cat "$ALLOWED_FILE")
if ! echo "$output" | grep -q "allowed content"; then
    echo "FAIL: Reading allowed file should succeed"
    exit 1
fi

# Test 6: Relative path normalization
# This test verifies that relative paths in --deny-file are normalized correctly
# Create a file and deny it using a relative path, then try to access it
RELATIVE_FILE="../relative_test.txt"
echo "relative test" > "$RELATIVE_FILE"

# Deny using relative path
if $BIN --deny-file-read "$RELATIVE_FILE" -- cat "$RELATIVE_FILE" > /dev/null 2>&1; then
    echo "FAIL: Relative path should be normalized and denied"
    rm -f "$RELATIVE_FILE"
    exit 1
fi

rm -f "$RELATIVE_FILE"

# Test 7: Append mode should be denied with --deny-file-write
APPEND_FILE="$TEMP_DIR/append.txt"
echo "initial" > "$APPEND_FILE"

if $BIN --deny-file-write "$APPEND_FILE" -- sh -c "echo 'appended' >> $APPEND_FILE" > /dev/null 2>&1; then
    echo "FAIL: Append to write-denied file should fail"
    exit 1
fi

# Content should remain unchanged
if ! grep -q "^initial$" "$APPEND_FILE"; then
    echo "FAIL: Content should remain unchanged after failed append"
    exit 1
fi

# Test 8: No file policy allows all access
NO_POLICY_FILE="$TEMP_DIR/no_policy.txt"
echo "test" > "$NO_POLICY_FILE"

# Should succeed without any deny flags
output=$($BIN --allow-network-all -- cat "$NO_POLICY_FILE")
if ! echo "$output" | grep -q "test"; then
    echo "FAIL: File access should be allowed by default"
    exit 1
fi

echo "All file access control tests passed!"
