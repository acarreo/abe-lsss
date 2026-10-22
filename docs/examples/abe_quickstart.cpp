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
