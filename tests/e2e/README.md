# E2E Tests

End-to-end tests for mori using shell scripts.

## Prerequisites

- **Linux**: root privileges (for loading eBPF programs)
- Built binary: `cargo build --release`

## Running Tests

```bash
# Run all tests
sudo ./run_tests.sh

# Run only network tests
sudo ./test_linux.sh

# Run only file access control tests
sudo ./test_file_access.sh
```

## Test Coverage

### Network Tests (`test_linux.sh`)

1. Network is blocked without `--allow-network`
2. Allowed domain can communicate
3. Non-allowed domain is blocked
4. Multiple entries - allowed domains work
5. IP address allowlist works
6. Domain with port specification

### File Access Control Tests (`test_file_access.sh`)

1. **`--deny-file-read` behavior**
   - Blocks reading the specified file
   - Allows writing to the specified file

2. **`--deny-file-write` behavior**
   - Blocks writing to the specified file
   - Allows reading the specified file

3. **`--deny-file` behavior**
   - Blocks both reading and writing to the specified file

4. **Multiple deny paths**
   - Different access modes coexist correctly
   - Each file enforces its specific deny policy

5. **Deny-list mode verification**
   - Files not in the deny list are allowed
   - Only explicitly denied files are blocked

6. **Relative path normalization**
   - Relative paths are converted to absolute paths
   - Deny policies work with relative path specifications

7. **Append mode handling**
   - Append operations (`>>`) are treated as write operations
   - `--deny-file-write` blocks append mode

8. **Default behavior**
   - No deny flags = all file access allowed
   - Deny-list mode semantics

## Access Mode Implementation

The tests verify that the eBPF program correctly checks file open modes:

```c
// eBPF code checks f_flags from struct file
let access_mode = f_flags & O_ACCMODE;

// Access mode values:
// O_RDONLY (0x0000) - read only
// O_WRONLY (0x0001) - write only
// O_RDWR   (0x0002) - read and write

// Policy matching:
// AccessMode::Read (1)      -> blocks O_RDONLY, O_RDWR
// AccessMode::Write (2)     -> blocks O_WRONLY, O_RDWR
// AccessMode::ReadWrite (3) -> blocks all modes
```

## Notes

- Tests use temporary files in `/tmp` (cleaned up automatically)
- All tests require root privileges
- Tests expect `target/release/mori` binary to exist
- Exit code 0 = all tests passed
- Non-zero exit code = test failure (with error message)
