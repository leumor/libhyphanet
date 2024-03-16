#include "libhyphanet/key/node.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/key.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <gsl/assert>
#include <gsl/util>
#include <iterator>
#include <optional>
#include <utility>
#include <vector>

namespace key::node {

// =============================================================================
// Key
// =============================================================================

double Key::to_normalized_double()
{
    if (cached_normalized_double_ > 0) { return cached_normalized_double_; }
    auto sha256 = crypto::Sha256();
    sha256.update(node_routing_key_);
    auto type = get_type();
    sha256.update(gsl::narrow_cast<std::byte>(type >> 8));
    sha256.update(gsl::narrow_cast<std::byte>(type));

    auto digest = sha256.digest();

    cached_normalized_double_ = support::util::key_digest_as_normalized_double(
        support::util::array_to_vector(digest));

    return cached_normalized_double_;
}

// =============================================================================
// Chk
// =============================================================================

std::vector<std::byte> Chk::get_full_key() const
{
    std::vector<std::byte> buf(full_key_length);

    auto type = get_type();
    buf[0] = static_cast<std::byte>(type >> 8);
    buf[1] = static_cast<std::byte>(type & 0xFF);

    const auto& routing_key = get_node_routing_key();

    Expects(routing_key.size() == full_key_length - 2);

    std::ranges::copy(routing_key, std::back_inserter(buf));

    return buf;
}

short Chk::get_type() const
{
    return static_cast<short>(
        static_cast<signed char>(base_type << 8)
        + static_cast<signed char>(
            static_cast<std::byte>(get_crypto_algorithm()) & std::byte{0xFF}));
}

std::unique_ptr<Key> Chk::archival_copy() const
{
    return std::make_unique<Chk>(*this);
}

// =============================================================================
// Ssk
// =============================================================================

Ssk::Ssk(const std::vector<std::byte>& user_routing_key,
         const std::array<std::byte, 32>& encrypted_hashed_docname,
         Crypto_algorithm algo, std::optional<std::vector<std::byte>> pub_key)
    : Key{algo},
      user_routing_key_{
          support::util::vector_to_array<std::byte, 32>(user_routing_key)},
      encrypted_hashed_docname_{encrypted_hashed_docname},
      pub_key_{std::move(pub_key)}
{
    Expects(user_routing_key.size() == 32);

    set_node_routing_key(
        make_routing_key(user_routing_key, encrypted_hashed_docname));
}

std::vector<std::byte>
Ssk::make_routing_key(const std::vector<std::byte>& user_routing_key,
                      const std::array<std::byte, 32>& encrypted_hashed_docname)
{
    using support::util::array_to_vector;

    auto sha256 = crypto::Sha256();
    sha256.update(array_to_vector(encrypted_hashed_docname));
    sha256.update(user_routing_key);
    return array_to_vector(sha256.digest());
}

std::vector<std::byte> Ssk::get_full_key() const
{
    std::vector<std::byte> buf(full_key_length);

    auto type = get_type();
    buf[0] = static_cast<std::byte>(type >> 8);
    buf[1] = static_cast<std::byte>(type & 0xFF);

    std::ranges::copy(encrypted_hashed_docname_, std::back_inserter(buf));
    std::ranges::copy(user_routing_key_, std::back_inserter(buf));

    return buf;
}

std::unique_ptr<Key> Ssk::archival_copy() const
{
    return std::make_unique<Archive_ssk>(
        support::util::array_to_vector(user_routing_key_),
        encrypted_hashed_docname_, get_crypto_algorithm());
}

short Ssk::get_type() const
{
    return static_cast<short>(
        static_cast<signed char>(base_type << 8)
        + static_cast<signed char>(
            static_cast<std::byte>(get_crypto_algorithm()) & std::byte{0xFF}));
}

std::vector<std::byte> Ssk::get_key_bytes() const
{
    return support::util::array_to_vector(encrypted_hashed_docname_);
}

} // namespace key::node