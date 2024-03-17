#include "libhyphanet/block.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/support.h"
#include <cstddef>
#include <gsl/assert>
#include <gsl/util>
#include <memory>
#include <vector>

namespace block {
namespace node {
    // =========================================================================
    // Key
    // =========================================================================

    // =========================================================================
    // Chk
    // =========================================================================
    Chk::Chk(const std::vector<std::byte>& data,
             const std::vector<std::byte>& headers,
             const std::shared_ptr<key::node::Chk>& node_key, bool verify,
             key::Crypto_algorithm algo)
        : Key(data, headers, node_key)
    {
        Expects(headers.size() == total_headers_length);

        if (node_key == nullptr || verify) {
            set_hash_identifier(gsl::narrow_cast<short>(
                static_cast<signed char>((headers.at(0) & std::byte{0xff}) << 8)
                + static_cast<signed char>(headers.at(1) & std::byte{0xff})));

            // Minimal verification
            // Check the hash
            if (get_hash_identifier() != hash_sha_256) {
                throw exception::Invalid_hash("Hash not SHA-256");
            }

            auto sha256 = crypto::Sha256();
            sha256.update(headers);
            sha256.update(data);
            auto hash = sha256.digest();

            auto hash_vec = support::util::array_to_vector(hash);

            if (node_key == nullptr) {
                set_node_key(std::make_shared<key::node::Chk>(hash_vec, algo));
            }
            else {
                auto check = get_node_key();
                if (check->get_node_routing_key() != hash_vec) {
                    throw exception::Invalid_hash("Hash does not verify");
                }
            }
        }
    }

    std::vector<std::byte> Chk::get_node_routing_key() const
    {
        return get_node_key()->get_node_routing_key();
    }

    std::vector<std::byte> Chk::get_full_key() const
    {
        return get_node_key()->get_full_key();
    }
} // namespace node
} // namespace block