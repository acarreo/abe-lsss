/**
 * @file api.h
 * @brief Process lifecycle and serialization options for abe-lsss.
 */

#ifndef ABE_LSSS_API_H
#define ABE_LSSS_API_H

#include <stdexcept>

namespace abe_lsss {

/**
 * @brief Initialize the RELIC-backed library.
 *
 * Call once before using pairing-based functionality. Throws std::runtime_error
 * @throws std::runtime_error if initialization fails or the library is
 * already initialized.
 */
void initialize();

/**
 * @brief Shut down the RELIC-backed library.
 *
 * Call once after all pairing-based operations have completed.
 * @throws std::runtime_error if shutdown fails.
 */
void shutdown();

/**
 * @brief Select compressed or uncompressed group-element serialization.
 *
 * The default is compressed. This process-global option must not be changed
 * while another thread is serializing group elements or between serialization
 * and deserialization of the same data.
 */
void set_compression(bool enabled) noexcept;

/**
 * @brief Return whether group-element serialization is compressed.
 */
bool compression_enabled() noexcept;

}

#endif
