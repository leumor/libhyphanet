#include "libhyphanet/key/user.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fmt/core.h>
#include <gsl/assert>
#include <gsl/util>
#include <limits>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace key::user {

// =============================================================================
// class Key
// =============================================================================

std::unique_ptr<Key> Key::create(const Uri& uri)
{
    std::unique_ptr<Key> key;
    const Token t{};

    bool is_insertable{false};
    if (auto extra = uri.get_extra();
        !extra.empty() && extra.size() >= 5 && extra.at(1) == std::byte{1}) {
        is_insertable = true;
    }

    switch (uri.get_uri_type()) {
        using enum key::Uri_type;
    case usk:
        if (is_insertable) { key = std::make_unique<Insertable_usk>(t); }
        else {
            key = std::make_unique<Usk>(t);
        }
        break;
    case ssk:
        if (is_insertable) { key = std::make_unique<Insertable_ssk>(t); }
        else {
            key = std::make_unique<Ssk>(t);
        }
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

    meta_strings_ = uri.get_meta_strings();

    check_invariants();
}

void Key::check_invariants() const
{
    if (routing_key_.empty()) {
        throw exception::Malformed_uri{
            "Invalid URI: missing routing key, crypto key or extra data"};
    }
}

std::optional<std::string> Key::pop_meta_strings()
{
    std::string meta_string;
    if (meta_strings_.empty()) { return std::nullopt; }
    meta_string = std::move(meta_strings_.front());
    meta_strings_.erase(meta_strings_.begin());
    return meta_string;
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
    if (auto docname = pop_meta_strings(); docname) {
        docname_ = std::move(*docname);
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
    if (auto routing_key = get_routing_key(); !routing_key.empty()) {
        if (auto new_key_hash = crypto::dsa::pub_key_hash(pub_key);
            get_routing_key() != support::util::array_to_vector(new_key_hash)) {
            throw std::invalid_argument{
                "New public key's hash does not match routing key"};
        }
    }

    pub_key_ = pub_key;
}

void Ssk::check_invariants() const
{
    // Verify pub_key_hash
    if (pub_key_) {
        auto pub_key_hash = crypto::dsa::pub_key_hash(*pub_key_);
        auto routing_key = get_routing_key();
        if (routing_key != support::util::array_to_vector(pub_key_hash)) {
            throw exception::Malformed_uri{
                "Invalid URI: invalid routing key or public key"};
        }
    }
}

Uri Ssk::to_uri() const
{
    auto uri = Subspace_key::to_uri();
    uri.set_uri_type(Uri_type::ssk);
    uri.append_meta_strings(get_meta_strings());
    return uri;
}

Uri Ssk::to_request_uri() const
{
    return this->to_uri();
}

std::optional<std::pair<std::string, long>> Ssk::parse_sitename_edition() const
{
    static const std::regex docname_with_edition_re{
        fmt::format("(.*)\\{}([0-9]+)", separator)};
    std::smatch match;

    if (auto docname = get_docname();
        std::regex_search(docname, match, docname_with_edition_re)) {
        return std::pair<std::string, long>{match[1], std::stol(match[2])};
    }
    return std::nullopt;
}

std::optional<Usk> Ssk::to_usk() const
{
    if (auto sitename_edition = parse_sitename_edition(); sitename_edition) {
        auto const& [sitename, edition] = *sitename_edition;

        Key_params params;
        params.routing_key = get_routing_key();
        params.crypto_key = get_crypto_key();
        params.crypto_algorithm = get_crypto_algorithm();
        params.meta_strings = get_meta_strings();

        return Usk{params, sitename, edition};
    }
    return std::nullopt;
}

std::unique_ptr<node::Node_key> Ssk::get_node_key() const
{
    // TODO Cache node key
    return std::make_unique<node::Node_ssk>(get_routing_key(),
                                            encrypted_hashed_docname_,
                                            get_crypto_algorithm(), pub_key_);
}

// =============================================================================
// class Insertable_ssk
// =============================================================================

void Insertable_ssk::init_from_uri(const Uri& uri)
{
    Ssk::init_from_uri(uri);

    const auto& extra = uri.get_extra();

    // Insertable should be 1, meaning that routing key in the uri is the
    // private key
    Expects(extra.at(1) == std::byte{1});

    set_priv_key(get_routing_key());
    set_routing_key(
        std::vector<std::byte>{}); // Disable pub_key/priv_key matching check

    auto pub_key = crypto::dsa::make_pub_key(get_priv_key());
    set_pub_key(pub_key);

    set_routing_key(
        support::util::array_to_vector(crypto::dsa::pub_key_hash(pub_key)));
}

Uri Insertable_ssk::to_uri() const
{
    auto uri = Ssk::to_uri();

    auto extra = uri.get_extra();
    // Insertable should be 1, meaning that routing key in the uri is the
    // private key
    extra[1] = std::byte{1};
    uri.set_extra(extra);

    uri.set_routing_key(get_priv_key());

    return uri;
}

Uri Insertable_ssk::to_request_uri() const
{
    auto uri = Ssk::to_uri();

    auto extra = uri.get_extra();
    extra[1] = std::byte{0};

    uri.set_extra(extra);

    return uri;
}

std::vector<std::byte> Insertable_ssk::get_extra_bytes() const
{
    auto bytes = Subspace_key::get_extra_bytes();

    // Insertable should be 1, meaning that routing key in the uri is the
    // private key
    bytes[1] = std::byte{1};

    return bytes;
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
    if (auto suggested_edition = pop_meta_strings(); suggested_edition) {
        try {
            suggested_edition_ = std::stol(*suggested_edition);
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
    uri.append_meta_string(std::to_string(suggested_edition_));
    uri.append_meta_strings(get_meta_strings());
    return uri;
}

Uri Usk::to_request_uri() const
{
    return this->to_uri();
}

Ssk Usk::to_ssk() const
{
    const long min_val = std::numeric_limits<long>::min();
    const long max_val = std::numeric_limits<long>::max();

    long edition = std::abs(suggested_edition_);

    if (edition == min_val) { edition = max_val; }

    Key_params params;
    params.routing_key = get_routing_key();
    params.crypto_key = get_crypto_key();
    params.crypto_algorithm = get_crypto_algorithm();
    params.meta_strings = get_meta_strings();

    auto docname = get_docname();

    return Ssk{
        params,
        fmt::format("{}{}{}", docname, Ssk::separator, edition),
    };
}

// =============================================================================
// class Insertable_usk
// =============================================================================

void Insertable_usk::init_from_uri(const Uri& uri)
{
    Usk::init_from_uri(uri);

    const auto& extra = uri.get_extra();

    // Insertable should be 1, meaning that routing key in the uri is the
    // private key
    Expects(extra.at(1) == std::byte{1});

    set_priv_key(get_routing_key());
    auto pub_key = crypto::dsa::make_pub_key(get_priv_key());

    set_routing_key(
        support::util::array_to_vector(crypto::dsa::pub_key_hash(pub_key)));
}

Uri Insertable_usk::to_request_uri() const
{
    auto uri = to_uri();

    auto extra = uri.get_extra();
    extra[1] = std::byte{0};

    uri.set_extra(extra);

    return uri;
}

std::vector<std::byte> Insertable_usk::get_extra_bytes() const
{
    auto bytes = Subspace_key::get_extra_bytes();

    // Insertable should be 1, meaning that routing key in the uri is the
    // private key
    bytes[1] = std::byte{1};

    return bytes;
}
// =============================================================================
// class Ksk
// =============================================================================

void Ksk::init_from_uri(const Uri& uri)
{
    set_meta_strings(uri.get_meta_strings());

    const auto& keyword = pop_meta_strings();
    if (!keyword) {
        throw exception::Malformed_uri{"Invalid URI: missing keyword"};
    }

    keyword_ = *keyword;

    crypto::Sha256 hasher;
    hasher.update(keyword_);
    set_crypto_key(hasher.digest());

    auto [priv_key_bytes, pub_key_bytes] = crypto::dsa::generate_keys();
    set_priv_key(priv_key_bytes);
    set_pub_key(pub_key_bytes);

    set_routing_key(support::util::array_to_vector(
        crypto::dsa::pub_key_hash(pub_key_bytes)));
}

Uri Ksk::to_uri() const
{
    Uri_params params;
    params.uri_type = Uri_type::ksk;
    params.meta_strings = {keyword_};

    auto uri = Uri{params};
    uri.append_meta_strings(get_meta_strings());

    return uri;
}

Uri Ksk::to_request_uri() const
{
    return this->to_uri();
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
    if (extra.size() != extra_length) {
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
    const auto compressor_value
        = gsl::narrow_cast<int16_t>(((std::to_integer<int>(byte_1) & 0xff) << 8)
                                    + (std::to_integer<int>(byte_2) & 0xff));

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

    auto uri = Uri{params};
    uri.append_meta_strings(get_meta_strings());

    return uri;
}

Uri Chk::to_request_uri() const
{
    return this->to_uri();
}

std::unique_ptr<node::Node_key> Chk::get_node_key() const
{
    // TODO Cache node key
    return std::make_unique<node::Node_chk>(get_routing_key(),
                                            get_crypto_algorithm());
}

} // namespace key::user
