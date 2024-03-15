#ifndef LIBHYPHANET_BLOCK_H
#define LIBHYPHANET_BLOCK_H

#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/key/user.h"
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

namespace block {

class Storable {
public:
    virtual ~Storable() = default;

    [[nodiscard]] virtual std::vector<std::byte> get_node_routing_key() = 0;
    [[nodiscard]] virtual std::vector<std::byte> get_full_key() = 0;
};

namespace node {
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
        [[nodiscard]] virtual std::optional<std::vector<std::byte>>
        get_pubkey_bytes() = 0;

        [[nodiscard]] std::shared_ptr<key::node::Key> get_node_key()
        {
            return node_key_;
        }

        /**
         * Retrieves the raw headers of the Key.
         *
         * @return the raw headers as a vector of bytes.
         */
        [[nodiscard]] std::vector<std::byte> get_raw_headers() const
        {
            return headers_;
        }

        /**
         * Retrieves the actual raw data of the Key.
         *
         * @return the raw data as a vector of bytes.
         */
        [[nodiscard]] virtual std::vector<std::byte> get_raw_data() const
        {
            return data_;
        }

        static const short hash_sha_256 = 1;
    protected:
        void set_raw_headers(const std::vector<std::byte>& headers)
        {
            headers_ = headers;
        }

        void set_raw_data(const std::vector<std::byte>& data) { data_ = data; }
    private:
        std::vector<std::byte> data_;
        std::vector<std::byte> headers_;

        std::shared_ptr<key::node::Key> node_key_;
    };

    /**
     * @brief CHK plus data. When fed a data::block::user::Chk, can decode into
     * the original data for a client.
     */
    class Chk : public Key {
    public:
        Chk(std::vector<std::byte> data, std::vector<std::byte> headers,
            std::shared_ptr<key::node::Chk> key = nullptr, bool verify = true,
            key::Crypto_algorithm algo
            = key::Crypto_algorithm::algo_aes_ctr_256_sha_256);

        [[nodiscard]] std::vector<std::byte> get_node_routing_key() override;
        [[nodiscard]] std::vector<std::byte> get_full_key() override;

        [[nodiscard]] std::optional<std::vector<std::byte>>
        get_pubkey_bytes() override
        {
            return std::nullopt;
        }

        static const size_t total_headers_length = 36;
        static const size_t data_length = 32768;

        /**
         * @brief Maximum length of compressed payload
         */
        static const size_t max_compressed_data_length = data_length - 4;
    };

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
        Ssk(std::vector<std::byte> data, std::vector<std::byte> headers,
            std::shared_ptr<key::node::Ssk> key, bool dont_verify);

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
    private:
        /**
         * @brief The index of the first byte of encrypted fields in the
         * headers, after E(H(docname)).
         */
        size_t headers_offset_;

        std::vector<std::byte> pub_key_;
    };
} // namespace node

namespace user {
    /**
     * @brief A Key Block with a key::user::Key. Can be decoded. Not a child of
     * data::block::node::Key because of issues with equals.
     *
     * @details
     * Two user key blocks with the same content but different keys are not
     * equals, therefore a user key block and its node key block have to be
     * not equals too. Hence it's really a different kind of object, so not a
     * child.
     */
    class Key {
    public:
        virtual ~Key() = default;

        /**
         * @brief Does the block contain metadata? If not, it contains real
         * data.
         */
        [[nodiscard]] virtual bool is_metadata() = 0;

        [[nodiscard]] virtual std::vector<std::byte> memory_decode() = 0;

        /**
         * @brief Get the key::user::Key for this block.
         *
         * @return std::shared_ptr<key::user::Key> The key::user::Key object
         */
        [[nodiscard]] std::shared_ptr<key::user::Key> get_user_key()
        {
            return user_key_;
        }

        /**
         * @brief Get the node key block for this block.
         *
         * @return std::shared_ptr<block::node::Key> The node key block
         */
        [[nodiscard]] std::shared_ptr<block::node::Key> get_node_block()
        {
            return node_block_;
        }

        /**
         * @brief Get the node key for this block.
         *
         * @return std::shared_ptr<key::node::Key> The node key
         */
        [[nodiscard]] std::shared_ptr<key::node::Key> get_node_key()
        {
            return node_block_->get_node_key();
        }
    private:
        std::shared_ptr<key::user::Key> user_key_;
        std::shared_ptr<block::node::Key> node_block_;
    };

    class Chk : public Key {};

    class Ssk : public Key {};

} // namespace user
} // namespace block

#endif /* LIBHYPHANET_BLOCK_H */
