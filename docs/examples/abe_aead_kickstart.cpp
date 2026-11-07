#include <abe_lsss/abe.h>

#include <iostream>
#include <memory>

static bool check(OpenABE_ERROR result, const char* operation) {
  if (result == OpenABE_NOERROR) {
    return true;
  }
  std::cerr << operation << ": " << OpenABE_errorToString(result) << '\n';
  return false;
}

static bool roundTrip() {
  auto context = abe_lsss::create_context(abe_lsss::cp_waters);
  auto policy = abe_lsss::parse_policy("(Engineering and ProjectA)");
  auto attributes = abe_lsss::parse_attributes("Engineering|ProjectA");
  if (!context || !policy || !attributes) {
    std::cerr << "Could not create the ABE context or parse its inputs\n";
    return false;
  }
  if (!check(context->generateParams("mpk", "msk"), "ABE setup") ||
      !check(context->keygen(attributes.get(), "alice", "mpk", "msk"),
             "ABE key generation")) {
    return false;
  }

  // Encrypt a random AES-256 key under the ABE policy.
  auto aesKey = std::make_shared<abe_lsss::SymmetricKey>();
  if (!aesKey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES)) {
    std::cerr << "Could not generate the AES key\n";
    return false;
  }
  abe_lsss::ByteString keyBytes = aesKey->getKeyBytes();
  abe_lsss::Ciphertext wrappedKey;
  if (!check(context->encrypt("mpk", policy.get(), keyBytes, wrappedKey),
             "ABE key encryption")) {
    return false;
  }

  // Authenticate the wrapped key along with the AES-GCM ciphertext.
  abe_lsss::ByteString aad;
  wrappedKey.exportToBytes(aad);
  abe_lsss::ByteString plaintext, ciphertext, iv, tag;
  plaintext.fromString("Hello from ABE and AES-GCM!");
  abe_lsss::AesGcmStream encryptor(DEFAULT_AES_SEC_LEVEL, aesKey);
  if (!check(encryptor.encryptInit(iv), "AES-GCM initialization")) {
    return false;
  }
  encryptor.initAddAuthData(aad.data(), aad.size());
  if (!check(encryptor.setAddAuthData(), "AES-GCM associated data") ||
      !check(encryptor.encryptUpdate(plaintext, ciphertext), "AES-GCM encryption") ||
      !check(encryptor.encryptFinalize(ciphertext, tag), "AES-GCM finalization")) {
    return false;
  }

  // Recover the AES key using Alice's attributes.
  abe_lsss::ByteString recoveredKeyBytes;
  if (!check(context->decrypt("mpk", "alice", recoveredKeyBytes, wrappedKey),
             "ABE key decryption")) {
    return false;
  }
  if (recoveredKeyBytes.size() != DEFAULT_SYM_KEY_BYTES) {
    std::cerr << "Invalid recovered AES key length\n";
    return false;
  }
  auto recoveredKey = std::make_shared<abe_lsss::SymmetricKey>();
  recoveredKey->setSymmetricKey(recoveredKeyBytes);

  // Do not use the recovered plaintext until the GCM tag has been verified.
  abe_lsss::ByteString recovered;
  abe_lsss::AesGcmStream decryptor(DEFAULT_AES_SEC_LEVEL, recoveredKey);
  if (!check(decryptor.decryptInit(iv, tag), "AES-GCM initialization")) {
    return false;
  }
  decryptor.initAddAuthData(aad.data(), aad.size());
  if (!check(decryptor.setAddAuthData(), "AES-GCM associated data") ||
      !check(decryptor.decryptUpdate(ciphertext, recovered), "AES-GCM decryption") ||
      !check(decryptor.decryptFinalize(recovered), "AES-GCM tag verification")) {
    return false;
  }
  if (recovered != plaintext) {
    std::cerr << "Recovered message does not match the original\n";
    return false;
  }
  std::cout << "Recovered: " << recovered.toString() << '\n';
  return true;
}

int main() {
  abe_lsss::initialize();
  const bool success = roundTrip();
  abe_lsss::shutdown();
  return success ? 0 : 1;
}
