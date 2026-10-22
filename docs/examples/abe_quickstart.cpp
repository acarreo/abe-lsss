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
