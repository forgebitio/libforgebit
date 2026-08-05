#!/usr/bin/env bash
# Format (or check) all C sources with clang-format.
# Usage:
#   ./scripts/format.sh          # rewrite in place
#   ./scripts/format.sh --check  # exit non-zero if any file needs formatting

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v clang-format >/dev/null 2>&1; then
    echo "clang-format not found. Install it (e.g. \`brew install clang-format\`)." >&2
    exit 1
fi

# Bash 3 (macOS /bin/bash) has no mapfile; collect paths with a plain loop.
FILES=()
while IFS= read -r path; do
    FILES+=("$path")
done <<EOF
$(find include src tests -type f \( -name '*.c' -o -name '*.h' \) | sort)
EOF

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "No C/H files found under include/, src/, or tests/." >&2
    exit 1
fi

MODE="${1:-}"
case "$MODE" in
    "" )
        clang-format -i --style=file "${FILES[@]}"
        echo "Formatted ${#FILES[@]} files."
        ;;
    --check )
        if clang-format --dry-run --Werror --style=file "${FILES[@]}" 2>&1; then
            echo "All ${#FILES[@]} files are correctly formatted."
        else
            echo "Formatting check failed. Run ./scripts/format.sh to fix." >&2
            exit 1
        fi
        ;;
    -h|--help )
        echo "Usage: $0 [--check]"
        exit 0
        ;;
    * )
        echo "Unknown option: $MODE (expected --check)" >&2
        exit 1
        ;;
esac
