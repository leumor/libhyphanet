#include "libhyphanet/keys/user.h"
#include "libhyphanet/keys.h"
#include <cryptopp/sha.h>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace keys::user {

std::unique_ptr<Key> Key::create_from_uri(const Uri& uri)
{
    switch (uri.get_uri_type()) {
        using enum keys::Uri_type;
    case usk:
        return std::make_unique<Usk>(uri);
    case ssk:
        return std::make_unique<Ssk>(uri);
    case chk:
        return std::make_unique<Chk>(uri);
    case ksk:
        return std::make_unique<Ksk>(uri);
    default:
        throw exception::Malformed_uri{"Invalid URI: unknown key type"};
    }
}

Key::Key(const Uri& uri)
{
    if (const auto& routing_key = uri.get_routing_key(); !routing_key.empty()) {
        routing_key_ = routing_key;
    }
    else {
        throw exception::Malformed_uri{
            "Invalid URI: missing routing key, crypto key or extra data"};
    }

    if (const auto& crypto_key = uri.get_crypto_key();
        crypto_key.size() == crypto_key_length) {
        std::ranges::copy(crypto_key, crypto_key_.begin());
    }
    else {
        throw exception::Malformed_uri{"Invalid URI: invalid crypto key"};
    }

    if (uri.get_extra().size() < extra_length) {
        throw exception::Malformed_uri{"Invalid URI: invalid extra data"};
    }
}

Insertable::~Insertable() = default;

Subspace_key::Subspace_key(const Uri& uri): Key(uri)
{
    if (uri.get_routing_key().size() != routing_key_size) {
        throw exception::Malformed_uri{"Invalid URI: invalid routing key"};
    }

    // Docname should be the first item of meta strings
    if (const auto& meta_strings = uri.get_meta_strings();
        !meta_strings.empty()) {
        docname_ = meta_strings.front();
    }
    else {
        throw exception::Malformed_uri{"Invalid URI: missing docname"};
    }
}

void Subspace_key::parse_algo(std::byte algo_byte)
{
    if (const int algo = std::to_integer<int>(algo_byte); algo == 2) {
        set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);
    }
    else if (algo == 3) {
        set_crypto_algorithm(Crypto_algorithm::algo_aes_ctr_256_sha_256);
    }
    else {
        throw exception::Malformed_uri{
            "Invalid URI: invalid Crypto algorithm in extra data"};
    }
}

Subspace_key::~Subspace_key() = default;

Usk::Usk(const Uri& uri): Subspace_key(uri)
{
    if (uri.get_uri_type() != Uri_type::usk) {
        throw exception::Malformed_uri{"Invalid URI: expected USK"};
    }

    const auto& extra = uri.get_extra();
    // TODO: Verify extra data
    parse_algo(extra.at(2));

    // Suggested edition number is the second item of meta strings
    if (const auto& meta_strings = uri.get_meta_strings();
        meta_strings.size() >= 2) {
        try {
            suggested_edition_ = std::stol(meta_strings.at(1));
        }
        catch (const std::invalid_argument&) {
            throw exception::Malformed_uri{
                "Invalid URI: invalid suggested edition number"};
        }
        catch (const std::out_of_range&) {
            suggested_edition_ = -1;
        }
    }
}

Ssk::Ssk(const Uri& uri): Subspace_key(uri)
{
    using namespace CryptoPP;

    // Calculate Encrypted Hashed Docname
}

std::vector<std::byte> Ssk::calculate_encrypted_hashed_docname(
    std::string_view docname,
    const std::array<std::byte, crypto_key_length>& crypto_key,
    const std::array<std::byte, routing_key_size>& routing_key,
    const std::optional<CryptoPP::DSA::PublicKey>& pub_key)
{
    using namespace CryptoPP;

    SHA256 hasher;

    // if (pub_key) {}
}

} // namespace keys::user
