#include "large_message_common.h"

#include <iostream>

namespace {

void runExample(std::uint64_t messageSize) {
  const std::filesystem::path messagePath = "file-1GB.dat";
  const std::filesystem::path recoveredPath = "file-1GB.abe-recovered.dat";
  large_message_example::createMessageFile(messagePath, messageSize);
  auto context = large_message_example::createCPContext();

  abe_lsss::ByteString plaintext =
      large_message_example::readMessageFile(messagePath, messageSize);
  auto policy = abe_lsss::parse_policy(large_message_example::kPolicy);
  if (!policy) {
    throw std::runtime_error("Could not parse the CP-ABE policy");
  }

  abe_lsss::Ciphertext ciphertext;
  large_message_example::requireSuccess(
      context->encrypt("mpk", policy.get(), plaintext, ciphertext),
      "Encrypting the message with CP-ABE");

  abe_lsss::ByteString recovered;
  large_message_example::requireSuccess(
      context->decrypt("mpk", "alice", recovered, ciphertext),
      "Decrypting the message with CP-ABE");
  if (recovered != plaintext) {
    throw std::runtime_error("The decrypted message does not match");
  }
  large_message_example::writeBytes(recoveredPath, recovered);

  std::cout << "CP-ABE " << messageSize / (1024 * 1024)
            << " MiB round trip succeeded: " << recoveredPath << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  bool initialized = false;
  try {
    const std::uint64_t messageSize =
        large_message_example::messageSizeFromArgs(argc, argv);
    abe_lsss::initialize();
    initialized = true;
    runExample(messageSize);
    abe_lsss::shutdown();
    initialized = false;
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
  } catch (OpenABE_ERROR error) {
    std::cerr << OpenABE_errorToString(error) << '\n';
  }

  if (initialized) {
    try {
      abe_lsss::shutdown();
    } catch (const std::exception& error) {
      std::cerr << "Library shutdown failed: " << error.what() << '\n';
    }
  }
  return 1;
}
