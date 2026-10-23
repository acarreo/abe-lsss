# abe-lsss

[![CI](https://github.com/acarreo/abe-lsss/actions/workflows/cmake-single-platform.yml/badge.svg?branch=main)](https://github.com/acarreo/abe-lsss/actions/workflows/cmake-single-platform.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![CMake project version](https://img.shields.io/badge/CMake%20project-2.1-informational.svg)](CMakeLists.txt)

`abe-lsss` is a C++ attribute-based encryption library derived from [Zeutro's OpenABE](https://github.com/zeutro/openabe). It combines the Waters ciphertext-policy and GPSW key-policy ABE constructions with an LSSS policy engine, using [RELIC](https://github.com/relic-toolkit/relic) for pairing-based arithmetic.

The repository is an evolving research/engineering project, not a security-certified product. The implementations currently exposed by the scheme factory are CPA ABE schemes. Do not infer CCA security, multi-authority support, or a completed independent cryptographic audit from this README.

## Documentation

- [API guide](docs/API.md) — namespaced C++ API, in-tree example and package integration.
- [CLI guide](docs/CLI.md) — setup, key generation, encryption and decryption.
- [Security model](docs/SECURITY_MODEL.md) — assumptions, intended properties and known limitations.
- [Security reporting](SECURITY.md) — private vulnerability reporting guidance.
- [Audit (Phase 0)](docs/AUDIT.md) — repository map, current limitations and priorities.
- [OpenABE design document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-design-doc.pdf) — upstream reference only; it is not a verified design specification for this fork.

## What is Attribute-Based Encryption (ABE)?

ABE encrypts to attributes and access policies rather than to one named public key. A user can decrypt only when the attributes or policy bound to their key satisfy the complementary information bound to the ciphertext.

- **Key-policy ABE (KP-ABE, content-based access):** attributes describe the encrypted content; a user's private key carries the access policy. This can grant access to a matching slice of stored data.
- **Ciphertext-policy ABE (CP-ABE, role/policy-based access):** a user's private key carries attributes; each ciphertext carries the access policy. This can enforce a policy chosen by the data owner.
- **Multi-authority ABE:** conceptually, several independent authorities issue attributes. Although OpenABE-derived types mention this model, no multi-authority scheme is instantiated by the current `abe-lsss` factory.

## What cryptographic algorithms are implemented?

| Scheme | Policy placement | Implementation security interface | Policy support |
|---|---|---|---|
| CP-ABE (Waters) | Ciphertext | CPA | Monotone AND/OR policy trees represented through LSSS; policy size affects ciphertext size. |
| KP-ABE (GPSW) | User key | CPA | Monotone AND/OR policy trees represented through LSSS; attribute-set size affects ciphertext size. |

The underlying ABE constructions are designed to resist collusion between users, but this fork has not received an independent cryptographic review. The active factory returns CPA contexts. Generic CCA code is disabled in the current source and CCA enum values alone do not enable CCA operation. No multi-authority, revocation, tracing, non-monotone policy, outsourced decryption, or searchable ABE scheme is currently provided.

Policies support monotone access trees and the parser has tests for date/integer expressions and ranges. The policy syntax is not a proof of support for arbitrary non-monotone circuits. Attribute labels are supplied as strings; practical policy size and group-element sizes constrain usage.

## What platforms are supported?

- **Linux:** the workflow configures GCC and Clang builds; the Linux GCC configuration and test suite were also run locally for the API/security changes.
- **macOS:** not covered by CI. The bundled RELIC x64 assembly (ELF directives) and the system Flex headers currently prevent a macOS build; this is a known open item.
- **Docker:** build recipes are provided, but they are not exercised by that CI workflow.
- **Other platforms:** not currently verified by repository CI.

## Installation

### Docker

Install Docker first. The Docker Makefile supports a RELIC curve and tag; `build_abe_lsss` builds the RELIC image if needed:

```bash
make -C docker build_abe_lsss CURVE=bls12-381 RELIC_TAG=0.6.0 ABE_LSSS_VERSION=2.1
```

To build an image from the **current local checkout**, rather than the repository clone used by the Dockerfile, build the RELIC image and run:

```bash
make -C docker build_relic CURVE=bls12-381 RELIC_TAG=0.6.0
make -C docker build_local CURVE=bls12-381 RELIC_TAG=0.6.0 ABE_LSSS_VERSION=2.1
```

See [docker/README.md](docker/README.md) for image names and details.

### Linux host

Requirements include CMake 3.10 or newer, a C++20 compiler, OpenSSL, GMP, Make and the RELIC build dependencies. `compile/` builds RELIC with `bls12-381` by default:

```bash
git clone https://github.com/acarreo/abe-lsss.git
cd abe-lsss

# Build and install RELIC; choose CURVE and RELIC_TAG here.
make -C compile CURVE=bls12-381 RELIC_TAG=0.6.0

# Configure and build abe-lsss. TESTS fetches GoogleTest when enabled.
cmake -S . -B build -DRELIC_CURVE=bls12-381 -DCLI=ON -DTESTS=ON -DBENCH=OFF
cmake --build build -- -j2

# Install to the default prefix (/usr/local); use sudo if needed.
sudo cmake --build build --target install
```

If RELIC has already been installed in a non-default prefix, pass its prefix through `CMAKE_PREFIX_PATH` when configuring. Otherwise CMake builds RELIC using `RELIC_CURVE` and `RELIC_TAG`, then installs it alongside abe-lsss. The separate `compile/Makefile` exposes `CURVE` and `RELIC_TAG`; **known limitation:** `compile/install-relic.sh` currently hardcodes tag `0.6.0`, overriding that Makefile's `RELIC_TAG` value.

### Using the installed package

The install includes the public headers, shared library, CMake package config and `abe-lsss.pc` pkg-config metadata. For a CMake consumer:

```cmake
find_package(abe-lsss CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE abe-lsss::abe_lsss)
```

When installed to a custom prefix, set `CMAKE_PREFIX_PATH` to that prefix. For a pkg-config consumer, use `pkg-config --cflags --libs abe-lsss`; add the custom prefix's `lib/pkgconfig` directory to `PKG_CONFIG_PATH` if needed. A minimal C++ example using the installed API is in [docs/API.md](docs/API.md).

By default, group elements are serialized compressed. The namespaced API can set the global compression option before serializing/loading data:

```cpp
#include <abe_lsss/api.h>

int main() {
  abe_lsss::initialize();
  abe_lsss::set_compression(false);
  // Use abe-lsss.
  abe_lsss::shutdown();
}
```

The process-global option is not per-context. Do not change it concurrently with serialization or use it to load data encoded with a different setting. OpenABE-named initialization and compression functions remain available as deprecated compatibility aliases.

## Quick Start

The in-tree CLI builds as `build/cli/abe-setup`, `abe-keygen`, `abe-encrypt` and `abe-decrypt`. These examples use the built programs and run from a fresh working directory.

```bash
mkdir -p /tmp/abe-lsss-demo
cd /tmp/abe-lsss-demo
printf 'ABE quick-start example\n' > message.txt
```

### CP-ABE

The policy belongs to the ciphertext; Alice receives attributes in her key.

```bash
/path/to/abe-lsss/build/cli/abe-setup   -s CP -p cp
/path/to/abe-lsss/build/cli/abe-keygen  -s CP -p cp -i 'Engineering|ProjectA' -o alice
/path/to/abe-lsss/build/cli/abe-encrypt -s CP -p cp -e '(Engineering and ProjectA)' \
  -i message.txt -o report
/path/to/abe-lsss/build/cli/abe-decrypt -s CP -p cp -k alice.key \
  -i report.cpabe -o recovered.txt
cmp message.txt recovered.txt
```

### KP-ABE

The policy belongs to the user's key; attributes are attached to each ciphertext.

```bash
/path/to/abe-lsss/build/cli/abe-setup   -s KP -p kp
/path/to/abe-lsss/build/cli/abe-keygen  -s KP -p kp \
  -i '(Engineering and (ProjectA or ProjectB))' -o auditor
/path/to/abe-lsss/build/cli/abe-encrypt -s KP -p kp -e 'Engineering|ProjectA' \
  -i message.txt -o record
/path/to/abe-lsss/build/cli/abe-decrypt -s KP -p kp -k auditor.key \
  -i record.kpabe -o recovered-kp.txt
cmp message.txt recovered-kp.txt
```

In these commands `-p` prefixes the master parameter filenames. Key files default to the `.key` suffix; ciphertext output names receive `.cpabe` or `.kpabe`. The CLI does not implement the legacy `PK` mode despite accepting its scheme name in some usage strings. For all current flags and caveats, see the [CLI guide](docs/CLI.md).

For an in-tree C++ example, see [docs/examples/abe_quickstart.cpp](docs/examples/abe_quickstart.cpp) and the [API guide](docs/API.md). The modern entry points are namespaced under `abe_lsss`; OpenABE-named lifecycle and compression functions remain available as deprecated compatibility aliases.

## Benchmarking

The Google Benchmark harness in `bench/` measures setup, key generation, encryption and decryption, reports policy/attribute counts, and records serialized master-public-key, user-key and ciphertext sizes. It uses 32-byte messages for the ABE workload. Install Google Benchmark first; `bench/google-benchmark.sh` shows one upstream build/install route.

```bash
cmake -S . -B build-bench -DCLI=OFF -DTESTS=OFF -DBENCH=ON
cmake --build build-bench --target bench_abe -- -j2
build-bench/bench/bench_abe \
  --benchmark_filter='BM_(Setup|Keygen)/(CP-ABE|KP-ABE)|BM_(Encrypt|Decrypt)/(CP-ABE|KP-ABE)/10$' \
  --benchmark_min_time=0.05 --benchmark_repetitions=3 \
  --benchmark_time_unit=ms \
  --benchmark_out=bench-results.json --benchmark_out_format=json
```

The following is a single local run on 22 October 2026, using RELIC `bls12-381`, mixed monotone policies with 10 leaves/10 attributes, 32-byte messages, three repetitions and 50 ms minimum per repetition. The host reported 20 CPUs at 4.8 GHz with CPU frequency scaling enabled. Values are the mean CPU/wall time in milliseconds; treat them as a reproducibility example, not a cross-machine performance claim.

| Curve | Scheme | Policy leaves | Attributes | Setup (ms) | Keygen (ms) | Encrypt (ms) | Decrypt (ms) | MPK (B) | User key (B) | Ciphertext (B) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BLS12-381 | CP-ABE | 10 | 10 | 1.29 | 2.66 | 5.25 | 2.79 | 688 | 973 | 2,023 |
| BLS12-381 | KP-ABE | 10 | 10 | 1.04 | 4.86 | 2.64 | 2.17 | 629 | 1,926 | 900 |

Sizes are raw serialized blobs returned by the library, not armored CLI file sizes. Benchmark values vary by compiler, machine, RELIC configuration and load; rerun with the command above before comparing revisions. The harness does not yet separate public-parameter setup costs from all runtime initialization costs.

## Project Structure

```text
📦 abe-lsss
 ┣ 📂bench      : benchmarks ABE et LSSS (Google Benchmark)
 ┣ 📂cli        : outils setup/keygen/encrypt/decrypt/policy
 ┣ 📂compile    : scripts de build et d'installation de RELIC
 ┣ 📂cmake      : templates du package CMake et pkg-config
 ┣ 📂docker     : Dockerfiles et Makefile des images
 ┣ 📂docs       : guides API/CLI, audit et exemple C++
 ┣ 📂include    : en-têtes ABE et LSSS
 ┣ 📂schemes    : implémentations CP-Waters et KP-GPSW
 ┣ 📂src        : cœur ABE et moteur LSSS
 ┣ 📂tests      : tests GoogleTest et vecteurs d'accès
 ┣ 📂utils      : utilitaires et types communs
 ┣ 📂.github    : workflow GitHub Actions
 ┣ 📜SECURITY.md
 ┣ 📜CMakeLists.txt
 ┣ 📜LICENSE
 ┗ 📜README.md
```

## Contributing

Contributions and focused bug reports are welcome. Please include the affected scheme, RELIC curve/version, compiler, exact build/test commands and whether the issue reproduces with a clean build. Do not post secret keys or sensitive plaintext in an issue. A fuller contributor guide, coverage reporting and static-analysis/format checks remain planned.

## Citation

Please cite the underlying construction(s) when using their cryptographic ideas:

```bibtex
@inproceedings{waters2011cpabe,
  author    = {Brent Waters},
  title     = {Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization},
  booktitle = {Public Key Cryptography -- PKC 2011},
  year      = {2011}
}

@inproceedings{goyal2006abe,
  author    = {Vipul Goyal and Omkant Pandey and Amit Sahai and Brent Waters},
  title     = {Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data},
  booktitle = {Proceedings of the 13th ACM Conference on Computer and Communications Security},
  year      = {2006}
}
```

These references identify the intended constructions; the relationship between each paper's full security proof and this fork's implementation has not been independently verified.

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting guidance and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the intended security properties and limitations. Do not disclose vulnerability details in a public issue.

## Contributions and credits

`abe-lsss` derives from OpenABE. Preserve its existing copyright and attribution notices. The upstream project credits the following cryptography designers and software developers:

- **Cryptography design:** Brent Waters, Matthew Green, Susan Hohenberger Waters and J. Ayo Akinyele.
- **Software design and development:** J. Ayo Akinyele, Matthew Green, Alan M. Dunn and Michael Rushanan.
- **Dependencies:** RELIC Toolkit; OpenSSL; GMP; GoogleTest for optional tests and Google Benchmark for optional benchmarks.

## Copyright and License

Copyright notices are retained from the upstream project. The repository is licensed under the [GNU Affero General Public License v3.0](LICENSE). See the license text for the complete terms.
