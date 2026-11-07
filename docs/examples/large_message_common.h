#ifndef ABE_LSSS_LARGE_MESSAGE_COMMON_H
#define ABE_LSSS_LARGE_MESSAGE_COMMON_H

#include <abe_lsss/abe.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace large_message_example {

inline constexpr std::uint64_t kMessageSize = 1ULL << 30;
inline constexpr std::size_t kIoBufferSize = 64 * 1024;
inline constexpr char kPolicy[] = "(Engineering and ProjectA)";
inline constexpr char kAttributes[] = "Engineering|ProjectA";

inline void requireSuccess(OpenABE_ERROR result, const std::string& operation) {
  if (result != OpenABE_NOERROR) {
    throw std::runtime_error(operation + ": " + OpenABE_errorToString(result));
  }
}

inline void createMessageFile(const std::filesystem::path& path,
                              std::uint64_t messageSize = kMessageSize) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("Cannot create " + path.string());
  }

  std::array<char, kIoBufferSize> block{};
  for (std::size_t i = 0; i < block.size(); ++i) {
    block[i] = static_cast<char>(i % 251);
  }

  for (std::uint64_t written = 0; written < messageSize;) {
    const auto blockSize = static_cast<std::size_t>(
        std::min<std::uint64_t>(block.size(), messageSize - written));
    output.write(block.data(), static_cast<std::streamsize>(blockSize));
    if (!output) {
      throw std::runtime_error("Failed writing " + path.string());
    }
    written += blockSize;
  }
}

inline OpenABEByteString readMessageFile(const std::filesystem::path& path,
                                         std::uint64_t messageSize) {
  if (std::filesystem::file_size(path) != messageSize) {
    throw std::runtime_error(path.string() + " has an unexpected size");
  }
  if (messageSize > std::numeric_limits<std::uint32_t>::max() ||
      messageSize > static_cast<std::uint64_t>(
                        std::numeric_limits<std::streamsize>::max())) {
    throw std::runtime_error("Message size exceeds the byte-string API limit");
  }

  OpenABEByteString contents;
  contents.resize(static_cast<std::size_t>(messageSize));
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("Cannot open " + path.string());
  }

  input.read(reinterpret_cast<char*>(contents.data()),
             static_cast<std::streamsize>(contents.size()));
  if (input.gcount() != static_cast<std::streamsize>(contents.size())) {
    throw std::runtime_error("Failed reading " + path.string());
  }
  return contents;
}

inline std::uint64_t messageSizeFromArgs(int argc, char** argv) {
  if (argc == 1) {
    return kMessageSize;
  }
  if (argc != 2) {
    throw std::runtime_error("Usage: example [size-in-MiB]");
  }

  std::size_t parsedLength = 0;
  const unsigned long long sizeMiB = std::stoull(argv[1], &parsedLength);
  if (parsedLength != std::string(argv[1]).size() || sizeMiB == 0 ||
      sizeMiB > std::numeric_limits<std::uint32_t>::max() / (1024ULL * 1024)) {
    throw std::runtime_error("The size must be a positive number of MiB");
  }
  return sizeMiB * 1024ULL * 1024;
}

inline OpenABEByteString readBytes(const std::filesystem::path& path) {
  const std::uint64_t size = std::filesystem::file_size(path);
  if (size > std::numeric_limits<std::uint32_t>::max()) {
    throw std::runtime_error(path.string() + " is too large to load");
  }
  OpenABEByteString contents;
  contents.resize(static_cast<std::size_t>(size));
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("Cannot open " + path.string());
  }
  input.read(reinterpret_cast<char*>(contents.data()),
             static_cast<std::streamsize>(contents.size()));
  if (input.gcount() != static_cast<std::streamsize>(contents.size())) {
    throw std::runtime_error("Failed reading " + path.string());
  }
  return contents;
}

inline void writeBytes(const std::filesystem::path& path,
                       const OpenABEByteString& contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("Cannot create " + path.string());
  }
  output.write(reinterpret_cast<const char*>(contents.data()),
               static_cast<std::streamsize>(contents.size()));
  if (!output) {
    throw std::runtime_error("Failed writing " + path.string());
  }
}

inline std::unique_ptr<abe_lsss::CpaContext> createCpContext() {
  auto context = abe_lsss::create_context(abe_lsss::cp_waters);
  if (!context) {
    throw std::runtime_error("Could not create the CP-ABE context");
  }

  requireSuccess(context->generateParams("mpk", "msk"),
                 "Generating CP-ABE parameters");
  auto attributes = abe_lsss::parse_attributes(kAttributes);
  auto policy = abe_lsss::parse_policy(kPolicy);
  if (!attributes || !policy) {
    throw std::runtime_error("Could not parse the CP-ABE inputs");
  }
  requireSuccess(context->keygen(attributes.get(), "alice", "mpk", "msk"),
                 "Generating the CP-ABE user key");
  return context;
}

inline void addAad(OpenABESymKeyAuthEncStream& stream,
                   const OpenABEByteString& aad) {
  OpenABEByteString mutableAad = aad;
  stream.initAddAuthData(mutableAad.data(),
                         static_cast<uint32_t>(mutableAad.size()));
  requireSuccess(stream.setAddAuthData(), "Setting AES-GCM associated data");
}

inline bool sameFiles(const std::filesystem::path& first,
                      const std::filesystem::path& second) {
  std::ifstream a(first, std::ios::binary);
  std::ifstream b(second, std::ios::binary);
  if (!a || !b) {
    return false;
  }
  std::array<char, kIoBufferSize> aBlock{};
  std::array<char, kIoBufferSize> bBlock{};
  while (a && b) {
    a.read(aBlock.data(), static_cast<std::streamsize>(aBlock.size()));
    b.read(bBlock.data(), static_cast<std::streamsize>(bBlock.size()));
    if (a.gcount() != b.gcount() ||
        !std::equal(aBlock.begin(), aBlock.begin() + a.gcount(),
                    bBlock.begin())) {
      return false;
    }
  }
  return a.eof() && b.eof();
}

}  // namespace large_message_example

#endif
