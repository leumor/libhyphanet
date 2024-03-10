#ifndef LIBHYPHANET_KEY_NODE_H
#define LIBHYPHANET_KEY_NODE_H

#include "libhyphanet/key.h"
#include <cstddef>
#include <libhyphanet/libhyphanet_export.h>
#include <vector>

namespace key::node {
class LIBHYPHANET_EXPORT Node_key {
protected:
    explicit Node_key(Crypto_algorithm algo): crypto_algorithm_(algo) {}
    Node_key(const std::vector<std::byte>& node_routing_key,
             Crypto_algorithm algo)
        : node_routing_key_(node_routing_key), crypto_algorithm_(algo)
    {}

    void set_node_routing_key(const std::vector<std::byte>& node_routing_key)
    {
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
};

class LIBHYPHANET_EXPORT Node_chk : public Node_key {
public:
    Node_chk(const std::vector<std::byte>& node_routing_key,
             Crypto_algorithm algo)
        : Node_key{node_routing_key, algo}
    {}

    static const std::byte base_type = std::byte{1};
    static const size_t key_length = 32;
    static const size_t full_key_length = 34;
};

class LIBHYPHANET_EXPORT Node_ssk : public Node_key {
public:
    Node_ssk(const std::vector<std::byte>& user_routing_key,
             const std::array<std::byte, 32>& encrypted_hashed_docname,
             Crypto_algorithm algo = Crypto_algorithm::algo_aes_ctr_256_sha_256,
             std::optional<std::vector<std::byte>> pub_key = std::nullopt);
    static const std::byte ssk_version = std::byte{1};
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
