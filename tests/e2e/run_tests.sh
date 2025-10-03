#!/usr/bin/env bash
# Run E2E tests based on platform

set -euo pipefail

cd "$(dirname "$0")"

case "$(uname -s)" in
    Linux)
        echo "Running network tests..."
        ./test_linux.sh
        echo ""
        echo "Running file access control tests..."
        ./test_file_access.sh
        ;;
    Darwin)
        exec ./test_macos.sh
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac
