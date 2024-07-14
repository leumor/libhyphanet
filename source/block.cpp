#include "libhyphanet/block.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <gsl/util>
#include <memory>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <vector>

namespace block::node {
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
    if (headers.size() != total_headers_length) {
        throw std::invalid_argument("Invalid header length.");
    }

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
            set_node_key(
                std::make_shared<key::node::impl::Chk>(hash_vec, algo));
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

// =========================================================================
// Ssk
// =========================================================================

Ssk::Ssk(const std::vector<std::byte>& data,
         const std::vector<std::byte>& headers,
         const std::shared_ptr<key::node::Ssk>& node_key, bool verify)
    : Key(data, headers, node_key)
{
    if (headers.size() != total_headers_length) {
        throw std::invalid_argument("Invalid header length.");
    }
    if (data.size() != data_length) {
        throw std::invalid_argument("Invalid data length.");
    }

    if (auto pub_key = node_key->get_pub_key(); pub_key != std::nullopt) {
        pub_key_ = *pub_key;
    }
    else {
        throw std::invalid_argument("PubKey was null.");
    }

    set_hash_identifier(gsl::narrow_cast<short>(
        static_cast<signed char>((headers.at(0) & std::byte{0xff}) << 8)
        + static_cast<signed char>(headers.at(1) & std::byte{0xff})));

    size_t x = 2;

    sym_cipher_identifier_ = gsl::narrow_cast<short>(
        static_cast<signed char>((headers.at(x) & std::byte{0xff}) << 8)
        + static_cast<signed char>(headers.at(x + 1) & std::byte{0xff}));

    x += 2;

    // Then E(H(docname))
    std::array<std::byte, e_h_docname_length> e_h_docname{};
    std::ranges::copy(headers.begin() + gsl::narrow_cast<long>(x),
                      headers.begin() + gsl::narrow_cast<long>(x)
                          + e_h_docname_length,
                      e_h_docname.begin());

    x += e_h_docname_length;

    headers_offset_ = x;

    x += encrypted_headers_length;

    // Extract the signature
    if (x + sig_r_length + sig_s_length > headers.size()) {
        throw std::invalid_argument("Headers too short.");
    }

    if (verify) {
        if (get_hash_identifier() != hash_sha_256) {
            throw exception::Invalid_hash("Hash not SHA-256");
        }

        std::array<std::byte, sig_r_length + sig_s_length> signature{};

        std::ranges::copy(headers.begin() + gsl::narrow_cast<long>(x),
                          headers.begin() + gsl::narrow_cast<long>(x)
                              + sig_r_length + sig_s_length,
                          signature.begin());

        // x isn't verified otherwise so no need to += sig_r_length +
        // sig_s_length

        // Compute the hash on the data
        crypto::Sha256 sha265;
        sha265.update(data);
        auto data_hash = sha265.digest();

        // All headers up to and not including the signature
        sha265.update(
            std::views::take(data, headers_offset_ + encrypted_headers_length));
        // Then the implicit data hash
        sha265.update(data_hash);
        // Makes the implicit overall hash
        auto overall_hash = sha265.digest();

        // Now verify it

        // We probably don't need to try both here...
        // but that's what the legacy code was doing...
        if (!(crypto::dsa::verify(
                  pub_key_,
                  crypto::dsa::truncate_hash(
                      support::util::array_to_vector(overall_hash)),
                  support::util::array_to_vector(signature))
              || crypto::dsa::verify(
                  pub_key_, support::util::array_to_vector(overall_hash),
                  support::util::array_to_vector(signature)))) {
            throw exception::Invalid_signature(
                "Signature verification failed for node-level SSK");
        }
    }

    if (e_h_docname != node_key->get_encrypted_hashed_docname()) {
        throw exception::Invalid_e_h_docname(
            "E(H(docname)) wrong - wrong key?");
    }
}
} // namespace block::node
