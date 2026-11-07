#include "large_message_common.h"

#include <array>
#include <iostream>

namespace {

constexpr char kCipherMagic[] = "ABE-GCM1";
constexpr std::size_t kIvSize = AES_BLOCK_SIZE;
constexpr std::size_t kTagSize = AES_BLOCK_SIZE;

class RemoveUnlessCommitted {
public:
  explicit RemoveUnlessCommitted(std::filesystem::path path)
      : path_(std::move(path)) {}

  ~RemoveUnlessCommitted() {
    if (!committed_) {
      std::error_code error;
      std::filesystem::remove(path_, error);
      if (error) {
        std::cerr << "Could not remove temporary file " << path_ << ": "
                  << error.message() << '\n';
      }
    }
  }

  void commit() { committed_ = true; }

private:
  std::filesystem::path path_;
  bool committed_ = false;
};

void encryptFile(const std::filesystem::path& inputPath,
                 const std::filesystem::path& outputPath,
                 const std::shared_ptr<OpenABESymKey>& key,
                 const OpenABEByteString& aad) {
  std::ifstream input(inputPath, std::ios::binary);
  std::fstream output(outputPath, std::ios::binary | std::ios::out |
                                      std::ios::trunc);
  if (!input || !output) {
    throw std::runtime_error("Cannot open input or AES-GCM output file");
  }

  output.write(kCipherMagic, sizeof(kCipherMagic) - 1);
  std::array<char, kIvSize + kTagSize> placeholder{};
  output.write(placeholder.data(), placeholder.size());

  OpenABESymKeyAuthEncStream stream(DEFAULT_AES_SEC_LEVEL, key);
  OpenABEByteString iv;
  large_message_example::requireSuccess(stream.encryptInit(iv),
                                        "Starting AES-GCM encryption");
  large_message_example::addAad(stream, aad);

  std::array<uint8_t, large_message_example::kIoBufferSize> inputBuffer{};
  while (input) {
    input.read(reinterpret_cast<char*>(inputBuffer.data()), inputBuffer.size());
    const std::streamsize bytesRead = input.gcount();
    if (bytesRead == 0) {
      break;
    }

    OpenABEByteString plaintextBlock;
    plaintextBlock.appendArray(inputBuffer.data(),
                               static_cast<uint32_t>(bytesRead));
    OpenABEByteString ciphertextBlock;
    large_message_example::requireSuccess(
        stream.encryptUpdate(plaintextBlock, ciphertextBlock),
        "Encrypting an AES-GCM block");
    output.write(reinterpret_cast<const char*>(ciphertextBlock.data()),
                 static_cast<std::streamsize>(ciphertextBlock.size()));
    if (!output) {
      throw std::runtime_error("Failed writing AES-GCM ciphertext");
    }
  }
  if (!input.eof()) {
    throw std::runtime_error("Failed reading the input message");
  }

  OpenABEByteString finalBlock, tag;
  large_message_example::requireSuccess(
      stream.encryptFinalize(finalBlock, tag), "Finalizing AES-GCM encryption");
  output.write(reinterpret_cast<const char*>(finalBlock.data()),
               static_cast<std::streamsize>(finalBlock.size()));
  if (iv.size() != kIvSize || tag.size() != kTagSize || !output) {
    throw std::runtime_error("Invalid AES-GCM IV/tag or output write failed");
  }

  output.seekp(sizeof(kCipherMagic) - 1);
  output.write(reinterpret_cast<const char*>(iv.data()), iv.size());
  output.write(reinterpret_cast<const char*>(tag.data()), tag.size());
  if (!output) {
    throw std::runtime_error("Failed writing the AES-GCM header");
  }
}

void decryptFile(const std::filesystem::path& inputPath,
                 const std::filesystem::path& outputPath,
                 const std::shared_ptr<OpenABESymKey>& key,
                 const OpenABEByteString& aad) {
  std::ifstream input(inputPath, std::ios::binary);
  if (!input) {
    throw std::runtime_error("Cannot open AES-GCM ciphertext");
  }

  std::array<char, sizeof(kCipherMagic) - 1> magic{};
  OpenABEByteString iv, tag;
  iv.resize(kIvSize);
  tag.resize(kTagSize);
  input.read(magic.data(), magic.size());
  input.read(reinterpret_cast<char*>(iv.data()), iv.size());
  input.read(reinterpret_cast<char*>(tag.data()), tag.size());
  if (!input || std::string(magic.data(), magic.size()) != kCipherMagic) {
    throw std::runtime_error("Invalid AES-GCM file header");
  }

  const std::filesystem::path temporaryPath = outputPath.string() + ".tmp";
  RemoveUnlessCommitted temporaryFile(temporaryPath);
  std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("Cannot create " + temporaryPath.string());
  }

  OpenABESymKeyAuthEncStream stream(DEFAULT_AES_SEC_LEVEL, key);
  large_message_example::requireSuccess(stream.decryptInit(iv, tag),
                                        "Starting AES-GCM decryption");
  large_message_example::addAad(stream, aad);

  std::array<uint8_t, large_message_example::kIoBufferSize> inputBuffer{};
  while (input) {
    input.read(reinterpret_cast<char*>(inputBuffer.data()), inputBuffer.size());
    const std::streamsize bytesRead = input.gcount();
    if (bytesRead == 0) {
      break;
    }

    OpenABEByteString ciphertextBlock;
    ciphertextBlock.appendArray(inputBuffer.data(),
                                static_cast<uint32_t>(bytesRead));
    OpenABEByteString plaintextBlock;
    large_message_example::requireSuccess(
        stream.decryptUpdate(ciphertextBlock, plaintextBlock),
        "Decrypting an AES-GCM block");
    output.write(reinterpret_cast<const char*>(plaintextBlock.data()),
                 static_cast<std::streamsize>(plaintextBlock.size()));
    if (!output) {
      throw std::runtime_error("Failed writing decrypted data");
    }
  }
  if (!input.eof()) {
    throw std::runtime_error("Failed reading AES-GCM ciphertext");
  }

  OpenABEByteString finalBlock;
  large_message_example::requireSuccess(stream.decryptFinalize(finalBlock),
                                        "Verifying the AES-GCM tag");
  output.write(reinterpret_cast<const char*>(finalBlock.data()),
               static_cast<std::streamsize>(finalBlock.size()));
  output.close();
  if (!output) {
    throw std::runtime_error("Failed closing decrypted output");
  }

  std::filesystem::rename(temporaryPath, outputPath);
  temporaryFile.commit();
}

void runExample(std::uint64_t messageSize) {
  const std::filesystem::path messagePath = "file-1GB.dat";
  const std::filesystem::path keyCipherPath = "file-1GB.aesgcm.key";
  const std::filesystem::path encryptedPath = "file-1GB.aesgcm";
  const std::filesystem::path recoveredPath = "file-1GB.aead-recovered.dat";
  large_message_example::createMessageFile(messagePath, messageSize);

  auto context = large_message_example::createCpContext();
  auto policy = abe_lsss::parse_policy(large_message_example::kPolicy);
  if (!policy) {
    throw std::runtime_error("Could not parse the CP-ABE policy");
  }

  auto generatedKey = std::make_shared<OpenABESymKey>();
  if (!generatedKey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES)) {
    throw std::runtime_error("Could not generate an AES-256 key");
  }
  OpenABEByteString keyBytes = generatedKey->getKeyBytes();
  OpenABECiphertext encryptedKey;
  large_message_example::requireSuccess(
      context->encrypt("mpk", policy.get(), keyBytes, encryptedKey),
      "Encrypting the AES key with CP-ABE");

  OpenABEByteString serializedKey;
  encryptedKey.exportToBytes(serializedKey);
  large_message_example::writeBytes(keyCipherPath, serializedKey);

  OpenABECiphertext loadedEncryptedKey;
  OpenABEByteString storedKeyCipher =
      large_message_example::readBytes(keyCipherPath);
  loadedEncryptedKey.loadFromBytes(storedKeyCipher);
  OpenABEByteString recoveredKeyBytes;
  large_message_example::requireSuccess(
      context->decrypt("mpk", "alice", recoveredKeyBytes, loadedEncryptedKey),
      "Decrypting the AES key with CP-ABE");
  if (recoveredKeyBytes.size() != DEFAULT_SYM_KEY_BYTES) {
    throw std::runtime_error("The decrypted AES key has an invalid size");
  }

  auto recoveredKey = std::make_shared<OpenABESymKey>();
  recoveredKey->setSymmetricKey(recoveredKeyBytes);
  OpenABEByteString aad;
  loadedEncryptedKey.getHeader(aad);
  encryptFile(messagePath, encryptedPath, generatedKey, aad);
  decryptFile(encryptedPath, recoveredPath, recoveredKey, aad);
  if (!large_message_example::sameFiles(messagePath, recoveredPath)) {
    throw std::runtime_error("The AEAD round trip did not match the input");
  }

  std::cout << "ABE + AES-GCM " << messageSize / (1024 * 1024)
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
