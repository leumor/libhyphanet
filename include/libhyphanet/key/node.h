#ifndef LIBHYPHANET_KEY_NODE_H
#define LIBHYPHANET_KEY_NODE_H

#include "libhyphanet/key.h"
#include <cstddef>
#include <gsl/assert>
#include <libhyphanet/libhyphanet_export.h>
#include <vector>

namespace key::node {

/**
 * @brief Base class for node keys.
 */
class LIBHYPHANET_EXPORT Key {
public:
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
    [[nodiscard]] virtual Key archival_copy() const = 0;

    /**
     * @brief Get key type
     *
     * @details
     * - High 8 bit (```(type >> 8) & 0xFF```) is the base type (Chk#base_type}
     *   or {Ssk#base_type).
     * - Low 8 bit (```type & 0xFF```) is the crypto algorithm. (Currently only
     *   Crypto_algorithm::algo_aes_pcfb_256_sha_256 is supported).
     *
     * @return std::byte the key type.
     */
    [[nodiscard]] virtual std::byte get_type() const = 0;

    [[nodiscard]] double to_normalized_double();

    [[nodiscard]] std::vector<std::byte> get_node_routing_key() const
    {
        return node_routing_key_;
    }

    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const
    {
        return crypto_algorithm_;
    }
protected:
    explicit Key(Crypto_algorithm algo): crypto_algorithm_(algo) {}

    Key(const std::vector<std::byte>& node_routing_key, Crypto_algorithm algo)
        : node_routing_key_(node_routing_key), crypto_algorithm_(algo)
    {
        Expects(!node_routing_key_.empty());
    }

    void set_node_routing_key(const std::vector<std::byte>& node_routing_key)
    {
        Expects(!node_routing_key.empty());
        node_routing_key_ = node_routing_key;
    }
private:
    /**
     * @brief Node Routing Key.
     *
     * @details
     * The **Node Routing Key** is based on the hash of the data or the
     * public key of the owner ([Client Routing
     * Key](#user::Key#routing_key_)), and it determines how close a node is
     * to the data. Nodes use the routing key to forward requests to the
     * node that is most responsible for storing the data, or the closest
     * one they know of.
     *
     * For [CHKs](#user::Chk), the **Node Routing Key** is the [Client Routing
     * Key](#user::Key#routing_key_).
     *
     * For [Subspace Keys](#user::Subspace_key), **Node Routing Key** is a
     * SHA-256 hash of the [Encrypted Hashed Document
     * Name](#user::Ssk#encrypted_hashed_docname_) and the [Client Routing
     * Key](#user::Key#routing_key_).
     */
    std::vector<std::byte> node_routing_key_;

    /**
     * @brief The cryptographic algorithm used for encryption/decryption.
     */
    Crypto_algorithm crypto_algorithm_{
        Crypto_algorithm::algo_aes_ctr_256_sha_256};

    double cached_normalized_double_{-1.0};
};

class LIBHYPHANET_EXPORT Chk : public Key {
public:
    Chk(const std::vector<std::byte>& node_routing_key, Crypto_algorithm algo)
        : Key{node_routing_key, algo}
    {}

    static const std::byte base_type = std::byte{1};
    static const size_t key_length = 32;
    static const size_t full_key_length = 34;
};

class LIBHYPHANET_EXPORT Ssk : public Key {
public:
    Ssk(const std::vector<std::byte>& user_routing_key,
        const std::array<std::byte, 32>& encrypted_hashed_docname,
        Crypto_algorithm algo = Crypto_algorithm::algo_aes_ctr_256_sha_256,
        std::optional<std::vector<std::byte>> pub_key = std::nullopt);

    static const std::byte ssk_version = std::byte{1};
    static const std::byte base_type = std::byte{2};
private:
    [[nodiscard]] static std::vector<std::byte>
    make_routing_key(const std::vector<std::byte>& user_routing_key,
                     const std::array<std::byte, 32>& encrypted_hashed_docname);

    std::array<std::byte, 32> user_routing_key_;
    std::array<std::byte, 32> encrypted_hashed_docname_{};
    std::optional<std::vector<std::byte>> pub_key_;
};
} // namespace key::node

#endif /* LIBHYPHANET_KEY_NODE_H */
