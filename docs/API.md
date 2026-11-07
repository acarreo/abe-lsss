# abe-lsss C++ API

The supported namespaced entry points are declared in [`abe_lsss/abe.h`](../include/abe_lsss/abe.h) and [`abe_lsss/api.h`](../include/abe_lsss/api.h). OpenABE types remain visible as aliases while the API migration is in progress.

## Initialization and lifecycle

Initialize RELIC before pairing-based operations and shut it down after they finish:

```cpp
#include <abe_lsss/api.h>

abe_lsss::initialize();
// Use RELIC-backed abe-lsss functionality.
abe_lsss::shutdown();
```

Lifecycle calls throw `std::runtime_error` on failure. The legacy `InitializeOpenABE` and `ShutdownOpenABE` functions remain available but are deprecated. `OpenABEStateContext` is a legacy interface whose per-thread lifecycle has not been validated; it is not a thread-safety guarantee.

`abe_lsss::set_compression(true)` selects compressed group-element serialization (the default); `false` selects uncompressed serialization. This is a global compatibility setting and must not be changed concurrently or between encoding and decoding a stored object. The legacy `set_compression_flag` and `OpenABE_GetCompressionOption` interfaces are deprecated.

## In-tree CP-ABE and KP-ABE example

The following example generates a key and ciphertext for each active CPA scheme, then checks that the intended user decrypts the plaintext.

```cpp
#include <abe_lsss/abe.h>

#include <iostream>
#include <memory>
#include <string>

static bool roundTrip(OpenABE_SCHEME scheme, const std::string& encryptionInput,
                      const std::string& keyInput) {
  auto context = abe_lsss::create_context(scheme);
  if (!context ||
      context->generateParams("mpk", "msk") != OpenABE_NOERROR) {
    return false;
  }

  auto encInput = scheme == abe_lsss::cp_waters
      ? abe_lsss::parse_policy(encryptionInput)
      : abe_lsss::parse_attributes(encryptionInput);
  auto decKeyInput = scheme == abe_lsss::cp_waters
      ? abe_lsss::parse_attributes(keyInput)
      : abe_lsss::parse_policy(keyInput);
  if (!encInput || !decKeyInput ||
      context->keygen(decKeyInput.get(), "alice", "mpk", "msk") != OpenABE_NOERROR) {
    return false;
  }

  abe_lsss::ByteString plaintext, recovered;
  plaintext.assign(32, 0x42);
  abe_lsss::Ciphertext ciphertext;
  if (context->encrypt("mpk", encInput.get(), plaintext, ciphertext) != OpenABE_NOERROR ||
      context->decrypt("mpk", "alice", recovered, ciphertext) != OpenABE_NOERROR) {
    return false;
  }
  return plaintext == recovered;
}

int main() {
  abe_lsss::initialize();
  const bool cp = roundTrip(abe_lsss::cp_waters,
                            "(Engineering and ProjectA)",
                            "Engineering|ProjectA");
  const bool kp = roundTrip(abe_lsss::kp_gpsw,
                            "Engineering|ProjectA",
                            "(Engineering and (ProjectA or ProjectB))");
  abe_lsss::shutdown();
  if (!cp || !kp) {
    std::cerr << "ABE round trip failed\n";
    return 1;
  }
  return 0;
}
```

After installing abe-lsss to a prefix, a consumer can link through CMake:

```cmake
find_package(abe-lsss CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE abe-lsss::abe_lsss)
```

The installed `abe-lsss.pc` file is also available to pkg-config consumers.

## Hybrid ABE and AES-GCM context

`abe_lsss::create_hybrid_context` creates a context for either `cp_waters` or
`kp_gpsw`, with the same setup, key management and input conventions as the CPA
context. Its `encrypt` and `decrypt` accept `ByteString` messages and one
`Ciphertext`. The ABE KEM derives the AES-256-GCM key; the ciphertext contains
the KEM components, GCM IV, encrypted payload and tag. The ABE header
(library version, scheme and UID) is authenticated as associated data.

```cpp
auto context = abe_lsss::create_hybrid_context(abe_lsss::cp_waters);
auto policy = abe_lsss::parse_policy("(Engineering and ProjectA)");
auto attributes = abe_lsss::parse_attributes("Engineering|ProjectA");
if (!context || !policy || !attributes) {
  throw std::runtime_error("Invalid context or inputs");
}
if (context->generateParams("mpk", "msk") != OpenABE_NOERROR ||
    context->keygen(attributes.get(), "alice", "mpk", "msk") != OpenABE_NOERROR) {
  throw std::runtime_error("ABE setup failed");
}
abe_lsss::ByteString message, recovered;
message.fromString("Hello");
abe_lsss::Ciphertext ciphertext;
if (context->encrypt("mpk", policy.get(), message, ciphertext) != OpenABE_NOERROR ||
    context->decrypt("mpk", "alice", recovered, ciphertext) != OpenABE_NOERROR) {
  throw std::runtime_error("Hybrid encryption or authentication failed");
}
```

Decryption returns no plaintext on failure, including when GCM authentication
fails. Empty and binary messages are supported. The one-shot API operates in
memory and individual payloads are limited to `INT_MAX` bytes.
Hybrid ciphertexts are not interchangeable with CPA ciphertexts.
The GCM tag authenticates the payload and ABE header; it does not directly
authenticate all KEM components. The hybrid context does not claim CCA security.

### Hybrid streaming

The same context supports streaming via `encryptInit` and `decryptInit`. The
ABE KEM ciphertext and IV are separate from the encrypted payload blocks;
`finalize` produces or verifies the tag. Store or transmit all four pieces:
the serialized KEM ciphertext, IV, ordered payload blocks and tag. Each `update`
replaces its output buffer and accepts at most `INT_MAX` bytes; input and output
must be different objects. An empty stream is valid. The total payload limit is
2^36 - 32 bytes per stream.

On encryption, initialize with an empty stream pointer, call `update` for each
block and then `finalize(tag)`. On decryption, initialize with the KEM
ciphertext and IV, call `update` for each ciphertext block, then call
`finalize(tag)`. Each method returns an `OpenABE_ERROR`; check every result.
Successful or failed finalization closes the stream. Destroy or reset its
pointer before initializing another operation.

**Decrypted blocks are provisional until `finalize(tag)` succeeds.** Keep
them in a quarantine buffer or temporary file inaccessible to consumers, and
discard them if any operation or authentication fails. A single GCM tag at
the end does not authenticate individual blocks as they arrive. A stream owns
its cryptographic state and may outlive the context used to initialize it.

See [`abe_hybrid_stream.cpp`](examples/abe_hybrid_stream.cpp) for a minimal
two-block example:

```bash
cmake -S . -B build -DEXAMPLES=ON
cmake --build build --target abe_hybrid_stream -j2
build/docs/examples/abe_hybrid_stream
```

## CP-ABE and AES-GCM kickstart

[`abe_aead_kickstart.cpp`](examples/abe_aead_kickstart.cpp) demonstrates how
to encrypt a random AES-256 key with CP-ABE, use it to protect a message with
AES-GCM, then recover the key and verify the message. The serialized ABE
ciphertext is authenticated as associated data. The example uses an in-memory
message; decrypted data must not be used before the GCM tag is verified.

```bash
cmake -S . -B build -DEXAMPLES=ON
cmake --build build --target abe_aead_kickstart -j2
build/docs/examples/abe_aead_kickstart
```

## Large-message examples

Build the two CP-ABE examples with `-DEXAMPLES=ON`:

```bash
cmake -S . -B build -DCLI=OFF -DTESTS=OFF -DBENCH=OFF -DEXAMPLES=ON
cmake --build build --target abe_large_message abe_aead_large_message -j2
mkdir -p /tmp/abe-lsss-large-message
cd /tmp/abe-lsss-large-message
/path/to/abe-lsss/build/docs/examples/abe_large_message
/path/to/abe-lsss/build/docs/examples/abe_aead_large_message
```

Each example generates a deterministic 1 GiB `file-1GB.dat` input by default
and verifies the recovered output. Pass a size in MiB for a smaller test run,
for example `abe_aead_large_message 1`. `abe_large_message` passes the whole
file through the ABE byte-string API. `abe_aead_large_message` ABE-encrypts a
random 32-byte AES key, then encrypts and decrypts the file with the library's
streaming AES-GCM implementation. It writes the wrapped key to
`file-1GB.aesgcm.key`, the authenticated ciphertext to `file-1GB.aesgcm`, and
the recovered file to `file-1GB.aead-recovered.dat`.
The direct ABE example keeps the message in memory; the AEAD example processes
it in blocks.

## Main concepts

- `abe_lsss::CPAContext` is the common context for the available CPA schemes.
- `abe_lsss::HybridContext` combines the ABE KEM with AES-256-GCM.
- `abe_lsss::create_context` creates CP-Waters or KP-GPSW contexts; unsupported schemes return an empty pointer.
- `abe_lsss::FunctionInput` is the common input abstraction. `parse_policy` parses policy expressions; `parse_attributes` parses pipe-separated labels. A parse failure returns an empty pointer.
- `keygen`, `encrypt` and `decrypt` return `OpenABE_ERROR` values. Check each result; do not treat a failed decryption as a valid plaintext.
- `abe_lsss::ByteString` is used for binary messages, keys and serialized blobs.
- `abe_lsss::SymmetricKey`, `abe_lsss::AES_GCM` and `abe_lsss::AES_GCM_Stream`
  alias the symmetric key and AES-GCM classes, including streaming operations.

The previous `CpaContext`, `AesGcm` and `AesGcmStream` aliases remain available
for source compatibility but are deprecated.

The public API currently has no CCA ABE context or multi-authority factory. OpenABE type and function aliases remain for source compatibility.
