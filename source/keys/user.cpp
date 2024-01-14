#include "libhyphanet/keys/user.h"
#include "libhyphanet/keys.h"
#include <cstddef>
#include <memory>
#include <stdexcept>

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
    if (auto routing_key = uri.get_routing_key(); !routing_key.empty()) {
        routing_key_ = std::move(routing_key);
    }
    else {
        throw exception::Malformed_uri{
            "Invalid URI: missing routing key, crypto key or extra data"};
    }

    if (auto crypto_key = uri.get_crypto_key();
        crypto_key.size() == crypto_key_length) {
        crypto_key_ = std::move(crypto_key);
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
    if (auto& meta_strings = uri.get_meta_strings(); !meta_strings.empty()) {
        set_docname(meta_strings.front());
    }
    else {
        throw exception::Malformed_uri{"Invalid URI: missing docname"};
    }
}
Subspace_key::~Subspace_key() = default;

Usk::Usk(const Uri& uri): Subspace_key(uri)
{
    if (uri.get_uri_type() != Uri_type::usk) {
        throw exception::Malformed_uri{"Invalid URI: expected USK"};
    }

    auto& extra = uri.get_extra();
    // TODO: Verify extra data
    if (int algo = std::to_integer<int>(extra.at(2)); algo == 2) {
        set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);
    }
    else if (algo == 3) {
        set_crypto_algorithm(Crypto_algorithm::algo_aes_ctr_256_sha_256);
    }
    else {
        throw exception::Malformed_uri{
            "Invalid URI: invalid Crypto algorithm in extra data"};
    }

    // Suggested edition number is the second item of meta strings
    if (auto& meta_strings = uri.get_meta_strings(); meta_strings.size() >= 2) {
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

} // namespace keys::user
