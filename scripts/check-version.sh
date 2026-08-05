#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
header_file="${root_dir}/include/forgebit/forgebit.h"
release_tag="${1:-}"

cmake_version="$(bash "${root_dir}/scripts/read-version.sh")"
header_major="$(sed -n 's/^#define FORGEBIT_VERSION_MAJOR[[:space:]][[:space:]]*\([0-9][0-9]*\).*/\1/p' "${header_file}")"
header_minor="$(sed -n 's/^#define FORGEBIT_VERSION_MINOR[[:space:]][[:space:]]*\([0-9][0-9]*\).*/\1/p' "${header_file}")"
header_patch="$(sed -n 's/^#define FORGEBIT_VERSION_PATCH[[:space:]][[:space:]]*\([0-9][0-9]*\).*/\1/p' "${header_file}")"

if [[ -z "${cmake_version}" || -z "${header_major}" || -z "${header_minor}" || -z "${header_patch}" ]]; then
    echo "Could not read the version from CMakeLists.txt and forgebit.h." >&2
    exit 1
fi

header_version="${header_major}.${header_minor}.${header_patch}"

if [[ "${cmake_version}" != "${header_version}" ]]; then
    echo "Version mismatch: CMakeLists.txt has ${cmake_version}, but forgebit.h has ${header_version}." >&2
    exit 1
fi

if [[ -n "${release_tag}" ]]; then
    if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Release tags must use the form vMAJOR.MINOR.PATCH; got ${release_tag}." >&2
        exit 1
    fi

    expected_tag="v${cmake_version}"
    if [[ "${release_tag}" != "${expected_tag}" ]]; then
        echo "Tag mismatch: expected ${expected_tag}, but got ${release_tag}." >&2
        exit 1
    fi
fi

echo "Version metadata is consistent (${cmake_version})."
