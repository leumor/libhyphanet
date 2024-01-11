#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <array>
#include <boost/algorithm/string/case_conv.hpp>
#include <gsl/assert>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
    Expects(!uri.empty());

    Uri_params url_params;

    std::string processed_uri{uri};
    std::string_view processed_uri_view{processed_uri};

    if (!no_trim) { ltrim(processed_uri_view); }

    // Strip ?max-size, ?type etc.
    // Un-encoded ?'s are illegal.
    rtrim(processed_uri_view, "?");

    if (uri.find('@') == std::string_view::npos
        || uri.find('/') == std::string_view::npos) {
        // Maybe an encoded URI
        try {
            processed_uri = url_decode(uri);
        }
        catch (const support::exception::Url_decode_error&) {
            throw exception::Malformed_uri{
                "Invalid URI: no @ or /, or @ or / is escaped but there are "
                "invalid escapes"};
        }
    }

    // Strip http(s):// and (web+|ext+)(freenet|hyphanet|hypha): prefix
    static const std::regex re{
        "^(https?://[^/]+/+)?(((ext|web)\\+)?(freenet|hyphanet|hypha):)?"};

    processed_uri = std::regex_replace(processed_uri, re, "",
                                       std::regex_constants::format_first_only);
    processed_uri_view = std::string_view{processed_uri};

    // Decode key_type_
    auto pos = processed_uri_view.find('@');
    if (pos == std::string_view::npos) {
        throw exception::Malformed_uri{"Invalid URI: no @"};
    }
    url_params.key_type = parse_key_type_str(processed_uri_view.substr(0, pos));
    processed_uri_view.remove_prefix(pos + 1);

    pos = processed_uri_view.find('/');
    if (pos != std::string_view::npos) {
        // Uri that contains RoutingKey,CryptoKey,ExtraData

        auto keys_str = processed_uri_view.substr(0, pos);
        processed_uri_view.remove_prefix(pos + 1);
    }
    // Decode meta_strings_
    std::vector<std::string> uri_paths;
    for (const auto uri_path: std::views::split(processed_uri_view, '/')) {
        std::string_view sv{uri_path.begin(), uri_path.end()};
        std::string s;
        try {
            s = url_decode(sv, true);
        }
        catch (const support::exception::Url_decode_error&) {
            throw exception::Malformed_uri{"Invalid URI: invalid meta string"};
        }
        if (!s.empty()) { uri_paths.push_back(std::move(s)); }
    }

    // std::optional<std::string_view> docname;
    // long suggested_edition = -1;
    // if (key_type != Uri_type::chk && !uri_paths.empty()) {
    //     docname = uri_paths.front();
    //     uri_paths.erase(uri_paths.begin());
    //     if (key_type == Uri_type::usk) {
    //         if (uri_paths.empty()) {
    //             throw exception::Malformed_uri{
    //                 "Invalid URI: No suggested edition number for USK"};
    //         }

    //         try {
    //             suggested_edition = std::stol(uri_paths.front());
    //         }
    //         catch (...) {
    //             throw exception::Malformed_uri{
    //                 "Invalid URI: Invalid suggested edition number for
    //                 USK"};
    //         }
    //     }
    // }
}

Uri_type Uri::parse_key_type_str(std::string_view str)
{
    using enum keys::Uri_type;

    Uri_type key_type{};

    auto key_type_str = std::string(str);
    boost::algorithm::to_lower(key_type_str);
    if (key_type_str == "usk") { key_type = usk; }
    else if (key_type_str == "ssk") {
        key_type = ssk;
    }
    else if (key_type_str == "chk") {
        key_type = chk;
    }
    else if (key_type_str == "ksk") {
        key_type = ksk;
    }
    else {
        throw exception::Malformed_uri{"Invalid URI: unknown key type"};
    }

    return key_type;
}

namespace user {
    Insertable::~Insertable() = default;
    Subspace_key::~Subspace_key() = default;
} // namespace user

} // namespace keys
