#ifndef LIBHYPHANET_BLOCK_NODE_H
#define LIBHYPHANET_BLOCK_NODE_H

#include "libhyphanet/key/node.h"
#include <cstddef>
#include <libhyphanet/libhyphanet_export.h>
#include <optional>
#include <vector>

namespace block::node {

class LIBHYPHANET_EXPORT Storable {
public:
    virtual ~Storable() = default;

    [[nodiscard]] virtual std::vector<std::byte> get_node_routing_key() const
        = 0;
    [[nodiscard]] virtual std::vector<std::byte> get_full_key() const = 0;
};

/**
 * @brief Abstract class for fetched blocks.
 *
 * @details
 * Can be decoded by using a key::user::Key to
 * construct a block::user::Key, which can then be decoded to a
 * block::Bucket.
 */
class Key : public Storable {
public:
    [[nodiscard]] virtual std::optional<std::vector<std::byte>> get_pub_key()
        = 0;

    [[nodiscard]] virtual std::shared_ptr<key::node::Key> get_node_key() const
        = 0;

    /**
     * Retrieves the raw headers of the Key.
     *
     * @return the raw headers as a vector of bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_raw_headers() const = 0;

    /**
     * Retrieves the actual raw data of the Key.
     *
     * @return the raw data as a vector of bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_raw_data() const = 0;

    [[nodiscard]] virtual short get_hash_identifier() const = 0;

    static const short hash_sha_256 = 1;
};

static const size_t ssk_data_decrypt_key_length = 32;

/**
 * @brief SSK plus data.
 *
 * @details
 * Can do a node-level verification. Can decode original data when fed a
 * data::block::user::Ssk.
 *
 * HEADERS FORMAT:
 * 2 bytes - hash ID
 * 2 bytes - symmetric cipher ID
 * 32 bytes - E(H(docname))
 * ENCRYPTED WITH E(H(docname)) AS IV:
 *  32 bytes - H(decrypted data), = data decryption key
 *  2 bytes - data length + metadata flag
 *  2 bytes - data compression algorithm or -1
 * IMPLICIT - hash of data
 * IMPLICIT - hash of remaining fields, including the implicit hash of
 *  data
 *
 * SIGNATURE ON THE ABOVE HASH:
 *  32 bytes - signature: R (unsigned bytes)
 *  32 bytes - signature: S (unsigned bytes)
 *
 * PLUS THE PUBKEY:
 *  Pubkey
 *  Group
 *
 */
class Ssk : public Key {
public:
    /**
     * @brief how much of the headers we compare in order to consider
     * two SSKBlocks equal.
     *
     * @details
     * It's necessary because the last 64 bytes need not be
     * the same for the same data and the same key (see comments above)
     *
     */
    static const size_t header_compare_to = 71;

    static const size_t data_length = 1024;

    /**
     * @brief Maximum length of compressed payload
     */
    static const size_t max_compressed_data_length = data_length - 2;

    static const size_t sig_r_length = 32;
    static const size_t sig_s_length = 32;
    static const size_t e_h_docname_length = 32;
    static const size_t encrypted_headers_length = 36;

    static const size_t total_headers_length = 2 + sig_r_length + sig_s_length
                                               + 2 + e_h_docname_length
                                               + ssk_data_decrypt_key_length;
};
namespace exception {
    class LIBHYPHANET_EXPORT Invalid_hash : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class LIBHYPHANET_EXPORT Invalid_signature : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class LIBHYPHANET_EXPORT Invalid_e_h_docname : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

} // namespace exception

namespace impl {} // namespace impl

} // namespace block::node

#endif /* LIBHYPHANET_BLOCK_NODE_H */
