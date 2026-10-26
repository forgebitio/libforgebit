# libforgebit

Offline license verification for C, or anything that can call a C ABI.

Forgebit checks Ed25519-signed compact JWS licenses on the device. It makes no
network calls and does not generate licenses or collect hardware IDs. Give it
your trusted public keys and a license, and it will tell you whether the license
is valid for your product right now.

|          |                                              |
|----------|----------------------------------------------|
| Language | C11                                          |
| Crypto   | [libsodium](https://libsodium.org) (Ed25519) |
| Header   | `#include <forgebit/forgebit.h>`             |
| Protocol | Forgebit Offline Verification Protocol v1    |

This is the portable native implementation. Language SDKs and game-engine
bindings can use the same ABI.

---

## What it does

- Verify the signature over the original compact JWS (`header.payload.signature`)
- Enforce `alg: "EdDSA"`, a known `kid`, required claims, time windows, and an
  optional HWID
- Return specific result codes for expired licenses, wrong products, bad
  signatures, and more
- Expose verified claims/features only after a successful verify

## What it does not do

- Talk to a server or discover revocation after issuance
- Stop a hostile machine from rolling the clock or patching your binary
- Collect machine identifiers or invent product-specific feature meaning

A valid result means the signed license is intact and passes its local rules. It
does not mean a server still considers the license active.

---

## Quick start

```c
#include <forgebit/forgebit.h>

forgebit_verifier *verifier = forgebit_verifier_create();
forgebit_verifier_add_key_base64url(verifier, "key_01", public_key_b64);

forgebit_verify_options options = FORGEBIT_VERIFY_OPTIONS_INIT;
options.expected_product = "widget";
options.expected_vendor = "acme";
options.current_time = 1785880800;
options.has_current_time = true;

forgebit_verify_result *result = NULL;
forgebit_verify(verifier, license, license_len, &options, &result);

if (forgebit_result_is_valid(result)) {
    const forgebit_json_value *features = forgebit_result_features(result);
    /* turn on only the feature keys your app knows about */
} else {
    fprintf(stderr, "%s\n", forgebit_result_code_name(forgebit_result_code_get(result)));
}

forgebit_verify_result_destroy(result);
forgebit_verifier_destroy(verifier);
```

There are two outcomes to check:

1. **`forgebit_status`** tells you whether the API call succeeded, or failed
   because of a bad call, allocation error, or similar problem.
2. **`forgebit_verify_result`** tells you whether the license is valid. Always
   inspect `forgebit_result_is_valid()` or `forgebit_result_code_get()` when
   status is `OK`.

A bad license is a normal result, not an exceptional API failure.

---

## Adding it to your project

Choose a prebuilt package when you are adding Forgebit to an application. Build
from source when you are vendoring it, working in a monorepo, or preparing a
package for a platform. Either way, your code includes the same header:

```c
#include <forgebit/forgebit.h>
```

### Use a prebuilt package

Ship or download a versioned archive for your OS and architecture, then point
your build at the extracted directory.

Produce an archive from this repo:

```bash
./scripts/package-prebuilt.sh
# → dist/forgebit-<version>-<os>-<arch>.tar.gz (+ .sha256)
```

Extract it somewhere stable, such as `/opt/forgebit` or
`third_party/forgebit`. The archive looks like this (the shared-library suffix
varies by platform):

```text
forgebit-<version>-<os>-<arch>/
  include/forgebit/forgebit.h
  lib/libforgebit.a
  lib/libforgebit.dylib
  lib/pkgconfig/forgebit.pc
  lib/cmake/Forgebit/ForgebitConfig.cmake
  lib/cmake/Forgebit/ForgebitConfigVersion.cmake
  lib/cmake/Forgebit/ForgebitTargets.cmake
  share/licenses/forgebit/LICENSE
```

**With CMake**

```cmake
cmake_minimum_required(VERSION 3.16)
project(app C)

find_package(Forgebit 0.1 REQUIRED)

add_executable(app main.c)
target_link_libraries(app PRIVATE Forgebit::forgebit)
```

```bash
cmake -S . -B build \
  -DCMAKE_PREFIX_PATH=/path/to/forgebit-0.2.0-darwin-arm64
```

**With pkg-config**

```bash
export PKG_CONFIG_PATH="/path/to/forgebit-<version>-<os>-<arch>/lib/pkgconfig:$PKG_CONFIG_PATH"
cc main.c $(pkg-config --cflags --libs forgebit) -o app
# Static linking also pulls in libsodium:
cc main.c $(pkg-config --static --cflags --libs forgebit) -o app
```

`Forgebit::forgebit` prefers the shared library when both are present. The
shared build links libsodium privately, but libsodium must still be available
at runtime. The static archive needs libsodium on the final link; CMake and
`pkg-config --static` handle that for you.

### Install from source

To install Forgebit into `/usr/local` or another system prefix, build it from a
checkout.

You will need **CMake 3.16 or newer**, a C11 compiler, **pkg-config**, and
**libsodium**. On macOS, you can install the build dependencies with:

```bash
brew install libsodium pkg-config cmake
```

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
cmake --install build
```

You can then use the same `find_package` or pkg-config setup without
`CMAKE_PREFIX_PATH`, provided the install prefix is on the relevant search path.

### Add the source to your build

This works well for vendored dependencies, monorepos, and package recipes. The
same build requirements apply.

For a vendored copy, add the directory directly:

```cmake
add_subdirectory(third_party/forgebit EXCLUDE_FROM_ALL)
target_link_libraries(your_app PRIVATE Forgebit::forgebit)
```

With CMake `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(forgebit
    GIT_REPOSITORY https://github.com/boone-studios/libforgebit.git
    GIT_TAG v0.2.0
)
set(FORGEBIT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(forgebit)
target_link_libraries(your_app PRIVATE Forgebit::forgebit)
```

### CMake targets

| Target | Linkage |
|--------|---------|
| `Forgebit::forgebit` | Shared when available, otherwise static |
| `Forgebit::shared` | Shared library only |
| `Forgebit::static` | Static library, with libsodium added to the final link |

---

## Practical tips

- Set **`expected_product`** (and usually **`expected_vendor`**) so a license meant
  for another app cannot unlock yours.
- Pass **`current_time`** explicitly in tests and security-sensitive hosts;
  otherwise the library reads the system clock.
- Use **`require_expiration`** if perpetual (no-`exp`) licenses should be rejected.
- Pass **`hardware_id`** when licenses may include an `hwid` claim.
- Feature values are opaque JSON. Only enable keys your application understands.

---

## Contributing

### Setup

```bash
# macOS; use the equivalent packages on other platforms
brew install libsodium pkg-config cmake clang-format
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Sanitizers:

```bash
cmake -S . -B build-asan -DFORGEBIT_ENABLE_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan
```

### Code style

The C source is formatted with **clang-format 22**. Please format it before
opening a PR:

```bash
./scripts/format.sh          # rewrite
./scripts/format.sh --check  # CI-friendly
# or: cmake --build build --target format / format-check
```

### What to change carefully

- **Public ABI** (`include/forgebit/forgebit.h`) — keep it stable; prefer new
  fields behind `struct_size` / opaque handles over breaking renames.
- **Result codes** — numeric values are permanent once published; never reuse a
  number for a new meaning.
- **Verification order** — follow the universal protocol’s step order
  (signature before trusting payload claims).
- **Tests** — add or extend cases under `tests/` (especially
  `test_vectors.c` for protocol behavior).

### Pull requests

1. Keep the diff focused (one concern per PR when practical).
2. Run tests (and sanitizers for anything touching parsers or crypto plumbing).
3. Run `./scripts/format.sh --check`.
4. Explain why the change is needed, not just what changed.

### Releases

Releases are built from tags in the form `vMAJOR.MINOR.PATCH`. Before tagging a
release, update the version in `CMakeLists.txt` and
`include/forgebit/forgebit.h`. CI checks that the two versions agree, and the
release workflow checks that the tag matches them.

Normative behavior is defined by Forgebit Offline Verification Protocol v1.

## License

Forgebit is available under the [MIT License](LICENSE).
