#ifndef LIBHYPHANET_KEY_NODE_H
#define LIBHYPHANET_KEY_NODE_H

#include "libhyphanet/key.h"
#include <cstddef>
#include <gsl/assert>
#include <libhyphanet/libhyphanet_export.h>
#include <memory>
#include <vector>

namespace key::node {

/**
 * @brief Base class for node keys.
 */
class LIBHYPHANET_EXPORT Key {
public:
    virtual ~Key() = default;

    /**
     * @brief Get the full key.
     *
     * @details
     * Including any crypto type bytes, everything needed to construct a Key
     * object.
     *
     * @return std::vector<std::byte> the full key bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_full_key() const = 0;

    /**
     * @brief Get a copy of the key with any unnecessary information stripped,
     * for long-term in-memory storage.
     *
     * @details
     * E.g. for SSKs, strips the DSAPublicKey. Copies it whether
     * we need to copy it because the original might pick up a pubkey after this
     * call. And the returned key will not accidentally pick up extra data.
     *
     * @return Key the copy of the key.
     */
    [[nodiscard]] virtual std::unique_ptr<Key> archival_copy() const = 0;

    /**
     * @brief Get key type
     *
     * @details
     * - High 8 bit (```(type >> 8) & 0xFF```) is the base type (Chk#base_type}
     *   or {Ssk#base_type).
     * - Low 8 bit (```type & 0xFF```) is the crypto algorithm. (Currently only
     *   Crypto_algorithm::algo_aes_pcfb_256_sha_256 is supported).
     *
     * @return short the key type.
     */
    [[nodiscard]] virtual short get_type() const = 0;

    /**
     * @brief Get the key bytes.
     *
     * @details
     * Not just the routing key, enough data to reconstruct the key (excluding
     * any pubkey needed).
     *
     * @return std::vector<std::byte> the key bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_key_bytes() const = 0;

    [[nodiscard]] virtual double to_normalized_double() = 0;

    [[nodiscard]] virtual const std::vector<std::byte>&
    get_node_routing_key() const
        = 0;
    [[nodiscard]] virtual Crypto_algorithm get_crypto_algorithm() const = 0;
};

class LIBHYPHANET_EXPORT Chk : public virtual Key {
public:
    static const std::byte base_type = std::byte{1};
    static const size_t key_length = 32;
    static const size_t full_key_length = 34;
};

class LIBHYPHANET_EXPORT Ssk : public virtual Key {
public:
    [[nodiscard]] virtual std::array<std::byte, 32>
    get_encrypted_hashed_docname() const = 0;

    [[nodiscard]] virtual std::optional<std::vector<std::byte>>
    get_pub_key() const = 0;

    static const std::byte ssk_version = std::byte{1};
    static const std::byte base_type = std::byte{2};
    static const size_t full_key_length = 66;
};

class LIBHYPHANET_EXPORT Archive_ssk : public virtual Ssk {};

} // namespace key::node

#endif /* LIBHYPHANET_KEY_NODE_H */
