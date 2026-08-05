#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cmake_file="${root_dir}/CMakeLists.txt"

version="$(sed -n 's/^project(forgebit VERSION \([0-9][0-9.]*\).*/\1/p' "${cmake_file}" | head -n 1)"

if [[ -z "${version}" ]]; then
    echo "Could not parse project version from CMakeLists.txt." >&2
    exit 1
fi

printf '%s\n' "${version}"
