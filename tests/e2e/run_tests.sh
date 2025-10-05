#!/usr/bin/env bash
# Run E2E tests based on platform

set -euo pipefail

cd "$(dirname "$0")"

case "$(uname -s)" in
    Linux)
        echo "Running network tests..."
        ./test_network_linux.sh
        echo ""
        echo "Running file access control tests..."
        ./test_file_access.sh
        ;;
    Darwin)
        ./test_network_macos.sh
        echo ""
        echo "Running file access control tests..."
        ./test_file_access.sh
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac
