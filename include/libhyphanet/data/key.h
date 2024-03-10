#ifndef LIBHYPHANET_DATA_KEY_H
#define LIBHYPHANET_DATA_KEY_H

#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

namespace data::block {
namespace node {
    class Key {
    public:
        virtual ~Key() = default;

        [[nodiscard]] virtual std::optional<std::vector<std::byte>>
        get_pubkey_bytes() = 0;

        [[nodiscard]] std::shared_ptr<key::node::Key> get_node_key()
        {
            return node_key_;
        }

        [[nodiscard]] std::vector<std::byte> get_raw_headers() const
        {
            return headers_;
        }

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

    class Chk : public Key {
    public:
        Chk(std::vector<std::byte> data, std::vector<std::byte> headers,
            std::shared_ptr<key::node::Chk> key = nullptr, bool verify = true,
            key::Crypto_algorithm algo
            = key::Crypto_algorithm::algo_aes_ctr_256_sha_256);
        static const size_t total_headers_length = 36;
        static const size_t data_length = 32768;
        static const size_t max_compressed_data_length = data_length - 4;
    };
} // namespace node
} // namespace data::block

#endif /* LIBHYPHANET_DATA_KEY_H */
