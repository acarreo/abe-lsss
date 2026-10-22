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

## Main concepts

- `abe_lsss::CpaContext` is the common context for the available CPA schemes.
- `abe_lsss::create_context` creates CP-Waters or KP-GPSW contexts; unsupported schemes return an empty pointer.
- `abe_lsss::FunctionInput` is the common input abstraction. `parse_policy` parses policy expressions; `parse_attributes` parses pipe-separated labels. A parse failure returns an empty pointer.
- `keygen`, `encrypt` and `decrypt` return `OpenABE_ERROR` values. Check each result; do not treat a failed decryption as a valid plaintext.
- `abe_lsss::ByteString` is used for binary messages, keys and serialized blobs.

The public API currently has no CCA ABE context or multi-authority factory. OpenABE type and function aliases remain for source compatibility.
