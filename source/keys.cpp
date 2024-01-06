#include "libhyphanet/keys.h"

namespace keys {

Uri::Uri(const Uri_params& url_params)
    : key_type_(url_params.key_type), routing_key_(url_params.routing_key),
      crypto_key_(url_params.crypto_key), extra_(url_params.extra),
      meta_strings_(url_params.meta_strings), docname_(url_params.docname),
      suggested_edition_(url_params.suggested_edition)
{
    // not implemented
}

namespace user {
    Insertable::~Insertable() = default;
    Subspace_key::~Subspace_key() = default;
} // namespace user

} // namespace keys
