# abe-lsss C++ API

This guide describes the API currently present in the source tree. It is not yet a stable, minimal installed SDK: the umbrella header retains OpenABE names, the scheme factory is declared in `utils/utils.h` rather than the installed headers, and scheme implementation sources are currently compiled into CLI/tests/bench separately from the shared library. These limits are tracked in the [Phase 0 audit](AUDIT.md).

## Initialization and lifecycle

The current global API names are inherited from OpenABE:

```cpp
#include <abe_lsss.h>

InitializeOpenABE();
// Use RELIC-backed abe-lsss functionality.
ShutdownOpenABE();
```

Initialization must happen before pairing operations. `OpenABEStateContext` also exposes per-thread setup/teardown; callers using RELIC from multiple threads must follow the installed RELIC lifecycle and should not assume the library is thread-safe.

`set_compression_flag(1)` selects compressed group-element serialization (the default); `set_compression_flag(0)` selects uncompressed serialization. This is a global compatibility setting and must not be changed concurrently or between encoding and decoding a stored object.

## In-tree CP-ABE and KP-ABE example

The following example generates a key and ciphertext for each active CPA scheme, then checks that the intended user decrypts the plaintext. `createContextABESchemeCPA`, `getEncInput` and `getKeyInput` are currently declared in the internal `utils/utils.h`; they are shown here to document the current repository API, not as a promise of a stable installed interface.

```cpp
#include <abe_lsss.h>
#include "utils/utils.h"

#include <iostream>
#include <memory>
#include <string>

static bool roundTrip(OpenABE_SCHEME scheme, const std::string& encryptionInput,
                      const std::string& keyInput) {
  auto context = createContextABESchemeCPA(scheme);
  if (!context ||
      context->generateParams("mpk", "msk") != OpenABE_NOERROR) {
    return false;
  }

  auto encInput = getEncInput(scheme, encryptionInput);
  auto decKeyInput = getKeyInput(scheme, keyInput);
  if (!encInput || !decKeyInput ||
      context->keygen(decKeyInput.get(), "alice", "mpk", "msk") != OpenABE_NOERROR) {
    return false;
  }

  OpenABEByteString plaintext, recovered;
  getRandomBytes(plaintext, 32);
  OpenABECiphertext ciphertext;
  if (context->encrypt("mpk", encInput.get(), plaintext, ciphertext) != OpenABE_NOERROR ||
      context->decrypt("mpk", "alice", recovered, ciphertext) != OpenABE_NOERROR) {
    return false;
  }
  return plaintext == recovered;
}

int main() {
  InitializeOpenABE();
  const bool cp = roundTrip(OpenABE_SCHEME_CP_WATERS,
                            "(Engineering and ProjectA)",
                            "Engineering|ProjectA");
  const bool kp = roundTrip(OpenABE_SCHEME_KP_GPSW,
                            "Engineering|ProjectA",
                            "(Engineering and (ProjectA or ProjectB))");
  ShutdownOpenABE();
  if (!cp || !kp) {
    std::cerr << "ABE round trip failed\n";
    return 1;
  }
  return 0;
}
```

With RELIC built in `.build/` and the library built there, compile from the repository root using the scheme sources explicitly:

```bash
c++ -std=c++20 -Iinclude -I. \
  -I.build/relic-src/include -I.build/relic-build/include \
  docs/examples/abe_quickstart.cpp \
  schemes/abecontext.cpp schemes/zcontextcpwaters.cpp schemes/zcontextkpgpsw.cpp \
  -L.build -Wl,-rpath,"$PWD/.build" \
  -L.build/relic-build/lib -Wl,-rpath,"$PWD/.build/relic-build/lib" \
  -labe_lsss -lrelic -lssl -lcrypto -lgmp -lrt \
  -o .build/abe-quickstart
./.build/abe-quickstart
```

This command is a source-tree example for the current Linux build layout. It is not a portable installed-package link command; a future packaging/API phase should add an exported CMake target and install the scheme factory/header.

## Main concepts

- `OpenABEContextSchemeCPA` is the common context for the available CPA schemes.
- `createContextABESchemeCPA` creates CP-Waters or KP-GPSW contexts.
- `OpenABEFunctionInput` is the common input abstraction. `createPolicyTree` parses policy expressions; `createAttributeList` parses pipe-separated labels.
- `keygen`, `encrypt` and `decrypt` return `OpenABE_ERROR` values. Check each result; do not treat a failed decryption as a valid plaintext.
- `OpenABEByteString` is used for binary messages, keys and serialized blobs.

The public API currently has no documented CCA ABE context, no multi-authority factory and no stable symbol/versioning guarantee. `InitializeOpenABE` and `ShutdownOpenABE` are legacy names; their replacement and compatibility aliases are reserved for a later API phase.
