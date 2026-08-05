#!/usr/bin/env bash
# Build a relocatable prebuilt archive that consumers can point at with
# CMAKE_PREFIX_PATH or PKG_CONFIG_PATH.
#
# Usage:
#   ./scripts/package-prebuilt.sh
#   ./scripts/package-prebuilt.sh --build-dir build-release --out dist
#
# Produces:
#   dist/forgebit-<version>-<os>-<arch>.tar.gz
#   dist/forgebit-<version>-<os>-<arch>.tar.gz.sha256

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT}/build-prebuilt"
OUT_DIR="${ROOT}/dist"
BUILD_TYPE=Release

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --debug) BUILD_TYPE=Debug; shift ;;
        -h|--help)
            echo "Usage: $0 [--build-dir DIR] [--out DIR] [--debug]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

VERSION="$(sed -n 's/^project(forgebit VERSION \([0-9.]*\).*/\1/p' "${ROOT}/CMakeLists.txt" | head -1)"
if [[ -z "${VERSION}" ]]; then
    echo "Could not parse project version from CMakeLists.txt" >&2
    exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
esac

STAGE="${BUILD_DIR}/stage"
PREFIX_NAME="forgebit-${VERSION}-${OS}-${ARCH}"
PREFIX="${STAGE}/${PREFIX_NAME}"

rm -rf "${STAGE}"
mkdir -p "${PREFIX}" "${OUT_DIR}"

cmake -S "${ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_INCLUDEDIR=include \
    -DCMAKE_INSTALL_BINDIR=bin \
    -DFORGEBIT_BUILD_TESTS=OFF \
    -DFORGEBIT_ENABLE_SANITIZERS=OFF

cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" -j
cmake --install "${BUILD_DIR}" --config "${BUILD_TYPE}"

ARCHIVE="${OUT_DIR}/${PREFIX_NAME}.tar.gz"
tar -C "${STAGE}" -czf "${ARCHIVE}" "${PREFIX_NAME}"

(
    cd "${OUT_DIR}"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${PREFIX_NAME}.tar.gz" > "${PREFIX_NAME}.tar.gz.sha256"
    else
        sha256sum "${PREFIX_NAME}.tar.gz" > "${PREFIX_NAME}.tar.gz.sha256"
    fi
)

echo "Wrote ${ARCHIVE}"
echo "Wrote ${OUT_DIR}/${PREFIX_NAME}.tar.gz.sha256"
echo
echo "Extract, then consume with:"
echo "  cmake -S <app> -B build -DCMAKE_PREFIX_PATH=/path/to/${PREFIX_NAME}"
echo "  export PKG_CONFIG_PATH=/path/to/${PREFIX_NAME}/lib/pkgconfig:\$PKG_CONFIG_PATH"
