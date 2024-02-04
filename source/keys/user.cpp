#include "libhyphanet/keys/user.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <gsl/util>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace keys::user {

// =============================================================================
// class Key
// =============================================================================

std::unique_ptr<Key> Key::create(const Uri& uri)
{
    std::unique_ptr<Key> key;
    const Token t{};

    switch (uri.get_uri_type()) {
        using enum keys::Uri_type;
    case usk:
        key = std::make_unique<Usk>(t);
        break;
    case ssk:
        key = std::make_unique<Ssk>(t);
        break;
    case chk:
        key = std::make_unique<Chk>(t);
        break;
    case ksk:
        key = std::make_unique<Ksk>(t);
        break;
    default:
        throw exception::Malformed_uri{"Invalid URI: unknown key type"};
    }

    key->init_from_uri(uri);
    return key;
}

void Key::init_from_uri(const Uri& uri)
{
    routing_key_ = uri.get_routing_key();

    const auto& crypto_key = uri.get_crypto_key();

    if (!crypto_key) {
        throw exception::Malformed_uri{"Invalid URI: invalid crypto key"};
    }

    std::ranges::copy(*crypto_key, crypto_key_.begin());

    check_invariants();
}

void Key::check_invariants() const
{
    if (routing_key_.empty()) {
        throw exception::Malformed_uri{
            "Invalid URI: missing routing key, crypto key or extra data"};
    }
}

// =============================================================================
// class Insertable
// =============================================================================

Insertable::~Insertable() = default;

// =============================================================================
// class Subspace_key
// =============================================================================

void Subspace_key::init_from_uri(const Uri& uri)
{
    Key::init_from_uri(uri);

    // Docname should be the first item of meta strings
    if (const auto& meta_strings = uri.get_meta_strings();
        !meta_strings.empty()) {
        docname_ = meta_strings.front();
    }

    // Subspace_key always uses algo_aes_pcfb_256_sha_256
    set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);

    if (const auto& extra = uri.get_extra();
        extra.size() != extra_length || extra != get_extra_bytes()) {
        throw exception::Malformed_uri{"Invalid URI: invalid extra data"};
    }

    check_invariants();

    get_routing_key().reserve(routing_key_size);
}

void Subspace_key::check_invariants() const
{
    if (get_routing_key().size() != routing_key_size) {
        throw exception::Malformed_uri{"Invalid URI: invalid routing key"};
    }

    if (docname_.empty()) {
        throw exception::Malformed_uri{"Invalid URI: missing docname"};
    }
}

std::vector<std::byte> Subspace_key::get_extra_bytes() const
{
    std::vector<std::byte> extra_bytes{
        std::byte{node::Node_ssk::ssk_version}, // Node SSK version
        std::byte{0}, // 0 = fetch (public) URI; 1 = insert (private) URI
        std::byte{
            static_cast<std::byte>(get_crypto_algorithm())}, // Crypto algorithm
        std::byte{
            static_cast<std::byte>(1 >> 8)}, // TODO: KeyBlock.HASH_SHA256 >> 8
        std::byte{1}, // TODO: KeyBlock.HASH_SHA256
    };

    return extra_bytes;
}

Uri Subspace_key::to_uri() const
{
    Uri_params params;
    params.routing_key = get_routing_key();
    params.crypto_key = get_crypto_key();
    params.extra = get_extra_bytes();
    params.meta_strings = {docname_};

    return Uri{params};
}

Subspace_key::~Subspace_key() = default;

// =============================================================================
// class Ssk
// =============================================================================

void Ssk::init_from_uri(const Uri& uri)
{
    Subspace_key::init_from_uri(uri);

    if (uri.get_uri_type() != Uri_type::ssk) {
        throw exception::Malformed_uri{"Invalid URI: expected USK"};
    }

    calculate_encrypted_hashed_docname();
    check_invariants();
}

void Ssk::calculate_encrypted_hashed_docname()
{
    crypto::Sha256 hasher;
    hasher.update(get_docname());
    const auto buf = hasher.digest();
    encrypted_hashed_docname_
        = crypto::rijndael256_256_encrypt(get_crypto_key(), buf);
}

void Ssk::set_pub_key(const std::vector<std::byte>& pub_key)
{
    if (pub_key_ && pub_key_ != pub_key) {
        throw std::invalid_argument{"Cannot reassign public key"};
    }

    if (auto new_key_hash = calculate_pub_key_hash(pub_key);
        !support::util::equal(get_routing_key(), new_key_hash)) {
        throw std::invalid_argument{
            "New public key's hash does not match routing key"};
    }

    pub_key_ = pub_key;
}

void Ssk::check_invariants() const
{
    // Verify pub_key_hash
    if (pub_key_) {
        auto pub_key_hash = calculate_pub_key_hash(*pub_key_);
        auto routing_key = get_routing_key();
        if (!support::util::equal(routing_key, pub_key_hash)) {
            throw exception::Malformed_uri{
                "Invalid URI: invalid routing key or public key"};
        }
    }
}

std::array<std::byte, 32>
Ssk::calculate_pub_key_hash(const std::vector<std::byte>& pub_key)
{
    crypto::Sha256 hasher;
    hasher.update(crypto::dsa::pub_key_bytes_to_mpi_bytes(pub_key));
    return hasher.digest();
}

Uri Ssk::to_uri() const
{
    auto uri = Subspace_key::to_uri();
    uri.set_uri_type(Uri_type::ssk);
    return uri;
}

node::Node_key Ssk::get_node_key() const
{
    // TODO
    return node::Node_key{};
}

// =============================================================================
// class Usk
// =============================================================================

void Usk::init_from_uri(const Uri& uri)
{
    Subspace_key::init_from_uri(uri);

    if (uri.get_uri_type() != Uri_type::usk) {
        throw exception::Malformed_uri{"Invalid URI: expected USK"};
    }

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

Uri Usk::to_uri() const
{
    auto uri = Subspace_key::to_uri();
    uri.set_uri_type(Uri_type::usk);
    auto meta_strings = uri.get_meta_strings();
    meta_strings.push_back(std::to_string(suggested_edition_));
    uri.set_meta_strings(meta_strings);
    return uri;
}

// =============================================================================
// class Ksk
// =============================================================================

void Ksk::init_from_uri(const Uri& uri)
{
    auto meta_strings = uri.get_meta_strings();

    if (meta_strings.size() < 2) {
        throw exception::Malformed_uri{"Invalid URI: missing keyword"};
    }

    const auto& keyword = meta_strings[0];
    if (keyword.empty()) {
        throw exception::Malformed_uri{"Invalid URI: missing keyword"};
    }

    crypto::Sha256 hasher;
    hasher.update(keyword);
    set_crypto_key(hasher.digest());

    auto [priv_key_bytes, pub_key_bytes] = crypto::dsa::generate_keys();
    set_priv_key(priv_key_bytes);
    set_pub_key(pub_key_bytes);

    hasher.update(crypto::dsa::pub_key_bytes_to_mpi_bytes(pub_key_bytes));
    auto pub_key_hash = hasher.digest();
    set_routing_key(support::util::array_to_vector(pub_key_hash));
}

Uri Ksk::to_uri() const
{
    Uri_params params;
    params.uri_type = Uri_type::ksk;
    params.meta_strings = {keyword_};

    return Uri{params};
}

// =============================================================================
// class Chk
// =============================================================================

void Chk::init_from_uri(const Uri& uri)
{
    Key::init_from_uri(uri);

    if (uri.get_uri_type() != Uri_type::chk) {
        throw exception::Malformed_uri{"Invalid URI: expected CHK"};
    }

    const auto& extra = uri.get_extra();
    if (extra.size() != extra_length || extra != get_extra_bytes()) {
        throw exception::Malformed_uri{"Invalid URI: invalid extra data"};
    }

    // byte 0 is reserved, for now

    // byte 1 is the crypto algorithm
    auto algo_byte = extra.at(1);
    parse_algo(algo_byte);

    // byte 2 is the control document flag
    control_document_ = (extra.at(2) & std::byte{0x02}) != std::byte{0};

    // byte 3 and 4 are the compress algorithm
    parse_compressor(extra.at(3), extra.at(4));
}

void Chk::parse_algo(std::byte algo_byte)
{
    if (!support::util::in_range(algo_byte, valid_crypto_algorithms)) {
        throw exception::Malformed_uri{
            "Invalid URI: invalid extra data (crypto algorithm)"};
    }

    set_crypto_algorithm(static_cast<Crypto_algorithm>(algo_byte));
}

void Chk::parse_compressor(std::byte byte_1, std::byte byte_2)
{
    const int compressor_value
        = std::to_integer<int>((byte_1 & std::byte{0xff}) << 8)
          + std::to_integer<int>(byte_2 & std::byte{0xff});

    using namespace support;

    if (!util::in_range(compressor_value, compressor::valid_compressor_types)) {
        throw exception::Malformed_uri{
            "Invalid URI: invalid extra data (compressor)"};
    }

    compressor_ = static_cast<compressor::Compressor_type>(compressor_value);
}

std::vector<std::byte> Chk::get_extra_bytes() const
{
    auto crypto_algorithm = static_cast<std::byte>(get_crypto_algorithm());
    auto compressor = static_cast<int>(compressor_);

    std::vector<std::byte> extra_bytes{
        crypto_algorithm >> 8, // Not used
        crypto_algorithm,
        control_document_ ? std::byte{2} : std::byte{0},
        gsl::narrow_cast<std::byte>(compressor >> 8),
        gsl::narrow_cast<std::byte>(compressor),
    };

    return extra_bytes;
}

Uri Chk::to_uri() const
{
    Uri_params params;
    params.uri_type = Uri_type::chk;
    params.routing_key = get_routing_key();
    params.crypto_key = get_crypto_key();
    params.extra = get_extra_bytes();

    return Uri{params};
}

node::Node_key Chk::get_node_key() const
{
    // TODO
    return node::Node_key{};
}

} // namespace keys::user
