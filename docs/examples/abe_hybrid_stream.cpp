#include <abe_lsss/abe.h>

#include <iostream>
#include <memory>

static bool check(OpenABE_ERROR result, const char* operation) {
  if (result == OpenABE_NOERROR) return true;
  std::cerr << operation << ": " << OpenABE_errorToString(result) << '\n';
  return false;
}

static bool roundTrip() {
  auto context = abe_lsss::create_hybrid_context(abe_lsss::cp_waters);
  auto policy = abe_lsss::parse_policy("(Engineering and ProjectA)");
  auto attributes = abe_lsss::parse_attributes("Engineering|ProjectA");
  if (!context || !policy || !attributes) {
    std::cerr << "Could not create the context or parse its inputs\n";
    return false;
  }
  if (!check(context->generateParams("mpk", "msk"), "Setup") ||
      !check(context->keygen(attributes.get(), "alice", "mpk", "msk"), "Key generation")) {
    return false;
  }

  abe_lsss::ByteString first, second, iv, tag, cipher1, cipher2;
  first.fromString("Hello from ");
  second.fromString("hybrid streaming!");
  abe_lsss::Ciphertext kem;
  std::unique_ptr<abe_lsss::HybridEncryptStream> encryptor;
  if (!check(context->encryptInit("mpk", policy.get(), kem, iv, encryptor), "Encryption init") ||
      !check(encryptor->update(first, cipher1), "Encrypt first block") ||
      !check(encryptor->update(second, cipher2), "Encrypt second block") ||
      !check(encryptor->finalize(tag), "Encryption finalize")) {
    return false;
  }

  std::unique_ptr<abe_lsss::HybridDecryptStream> decryptor;
  abe_lsss::ByteString block, quarantined;
  if (!check(context->decryptInit("mpk", "alice", kem, iv, decryptor), "Decryption init") ||
      !check(decryptor->update(cipher1, block), "Decrypt first block")) {
    return false;
  }
  quarantined += block;
  if (!check(decryptor->update(cipher2, block), "Decrypt second block")) {
    quarantined.zeroize();
    return false;
  }
  quarantined += block;
  if (!check(decryptor->finalize(tag), "Verify tag")) {
    quarantined.zeroize();
    return false;
  }

  abe_lsss::ByteString expected = first + second;
  if (quarantined != expected) {
    std::cerr << "Recovered message does not match\n";
    return false;
  }
  std::cout << "Recovered: " << quarantined.toString() << '\n';
  return true;
}

int main() {
  abe_lsss::initialize();
  const bool success = roundTrip();
  abe_lsss::shutdown();
  return success ? 0 : 1;
}
