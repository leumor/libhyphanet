#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <array>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <gsl/assert>
#include <utility>

using namespace support::util;

namespace keys {

Uri::Uri(Uri_params url_params)
    : key_type_{url_params.key_type},
      routing_key_{std::move(url_params.routing_key)},
      crypto_key_{std::move(url_params.crypto_key)},
      extra_{std::move(url_params.extra)}, docname_{url_params.docname},
      meta_strings_{std::move(url_params.meta_strings)}
{
    using enum keys::Uri_type;

    if (in_range(key_type_, std::array<Uri_type, 3>{chk, ssk, usk})) {
        // CHK, SSK and USKs require routing key, crypto key and extra data
        Expects(routing_key_ && crypto_key_ && extra_);

        // CHK routing key length check
        if (key_type_ == chk) {
            Expects(routing_key_->size() == user::Chk::routing_key_length);
        }

        // Crypto key length check
        Expects(crypto_key_->size() == user::Key::crypto_key_length);

        // Extra data length check
        Expects(extra_->size() >= user::Key::extra_length);
    }
    else if (key_type_ == ksk) {
        // KSK should not have routing key or crypto key or extra data
        Expects(!routing_key_ && !crypto_key_ && !extra_);

        // KSK should have a docname (keyword)
        Expects(docname_);
    }
}

Uri::Uri(std::string_view uri, bool no_trim)
{
    // if (!no_trim) { boost::algorithm::trim(uri); }
}

namespace user {
    Insertable::~Insertable() = default;
    Subspace_key::~Subspace_key() = default;
} // namespace user

} // namespace keys
