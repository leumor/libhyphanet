#include "libhyphanet/keys/user.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace keys::user {

std::unique_ptr<Key> Key::create(const Uri& uri)
{
    std::unique_ptr<Key> key;
    Token t{};

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
    if (uri.get_extra().size() < extra_length) {
        throw exception::Malformed_uri{"Invalid URI: invalid extra data"};
    }

    routing_key_ = uri.get_routing_key();

    const auto& crypto_key = uri.get_crypto_key();
    std::ranges::copy(crypto_key, crypto_key_.begin());

    check_invariants();
}

void Key::check_invariants() const
{
    if (routing_key_.empty()) {
        throw exception::Malformed_uri{
            "Invalid URI: missing routing key, crypto key or extra data"};
    }

    if (crypto_key_.size() != crypto_key_length) {
        throw exception::Malformed_uri{"Invalid URI: invalid crypto key"};
    }
}

Insertable::~Insertable() = default;

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
        extra.size() != 5 || extra != get_extra_bytes()) {
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

std::vector<std::byte> Subspace_key::get_extra_bytes()
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

Subspace_key::~Subspace_key() = default;

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
void Chk::parse_algo(std::byte algo_byte)
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
} // namespace keys::user
