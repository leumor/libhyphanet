#include "libhyphanet/keys/node.h"
#include "libhyphanet/crypto.h"
#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <cstddef>
#include <gsl/assert>
#include <utility>
#include <vector>

namespace keys::node {

// =============================================================================
// Node_ssk
// =============================================================================

Node_ssk::Node_ssk(const std::vector<std::byte>& user_routing_key,
                   const std::array<std::byte, 32>& encrypted_hashed_docname,
                   Crypto_algorithm algo,
                   std::optional<std::vector<std::byte>> pub_key)
    : Node_key{algo},
      user_routing_key_{
          support::util::vector_to_array<std::byte, 32>(user_routing_key)},
      encrypted_hashed_docname_{encrypted_hashed_docname},
      pub_key_{std::move(pub_key)}
{
    Expects(user_routing_key.size() == 32);

    set_node_routing_key(
        make_routing_key(user_routing_key, encrypted_hashed_docname));
}

std::vector<std::byte> Node_ssk::make_routing_key(
    const std::vector<std::byte>& user_routing_key,
    const std::array<std::byte, 32>& encrypted_hashed_docname)
{
    using support::util::array_to_vector;

    auto sha256 = crypto::Sha256();
    sha256.update(array_to_vector(encrypted_hashed_docname));
    sha256.update(user_routing_key);
    return array_to_vector(sha256.digest());
}
} // namespace keys::node