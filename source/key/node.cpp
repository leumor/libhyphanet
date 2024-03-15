#include "libhyphanet/key/node.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/key.h"
#include "libhyphanet/support.h"
#include <array>
#include <cstddef>
#include <gsl/assert>
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
    sha256.update(type >> 8);
    sha256.update(type);

    auto digest = sha256.digest();

    cached_normalized_double_ = support::util::key_digest_as_normalized_double(
        support::util::array_to_vector(digest));

    return cached_normalized_double_;
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
} // namespace key::node