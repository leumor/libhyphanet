#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include "libhyphanet/support/base64.h"
#include <boost/algorithm/string/case_conv.hpp>
#include <cstddef>
#include <gsl/assert>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace support::util;

namespace keys {

Uri::Uri(Uri_params url_params)
    : uri_type_{url_params.uri_type},
      routing_key_{std::move(url_params.routing_key)},
      crypto_key_{std::move(url_params.crypto_key)},
      extra_{std::move(url_params.extra)},
      meta_strings_{std::move(url_params.meta_strings)}
{
    // routing_key_ and crypto_key_ and extra_ are all existent or non-existent
    Expects(
        (!routing_key_.empty() && !crypto_key_.empty() && !extra_.empty())
        || (!routing_key_.empty() && !crypto_key_.empty() && !extra_.empty()));

    // TODO: move the checks to the constructor of Child classes
    // using enum keys::Uri_type;

    // if (in_range(uri_type_, std::array<Uri_type, 3>{chk, ssk, usk})) {
    //     // CHK, SSK and USKs require routing key, crypto key and extra data
    //     Expects(routing_key_ && crypto_key_ && extra_);

    //     // CHK routing key length check
    //     if (uri_type_ == chk) {
    //         Expects(routing_key_->size() == user::Chk::routing_key_length);
    //     }

    //     // Crypto key length check
    //     Expects(crypto_key_->size() == user::Key::crypto_key_length);

    //     // Extra data length check
    //     Expects(extra_->size() >= user::Key::extra_length);
    // }
    // else if (uri_type_ == ksk) {
    //     // KSK should not have routing key or crypto key or extra data
    //     Expects(!routing_key_ && !crypto_key_ && !extra_);

    //     // KSK should have a docname (keyword)
    //     Expects(docname_);
    // }
}

std::unique_ptr<Uri> Uri::create(std::string_view uri, bool no_trim)
{
    Expects(!uri.empty());

    Uri_params uri_params;

    // BEGIN Preprocessing the URI
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

    const auto processed_uri_const = std::regex_replace(
        processed_uri, re, "", std::regex_constants::format_first_only);
    // END Preprocessing the URI

    // BEGIN Parsing the URI
    processed_uri_view = std::string_view{processed_uri_const};

    // Decode key_type_
    auto pos = processed_uri_view.find('@');
    if (pos == std::string_view::npos) {
        throw exception::Malformed_uri{"Invalid URI: no @"};
    }
    uri_params.uri_type = parse_uri_type_str(processed_uri_view.substr(0, pos));
    processed_uri_view.remove_prefix(pos + 1);

    std::string_view uri_path;

    pos = processed_uri_view.find(uri_separator);
    if (pos != std::string_view::npos) {
        // URI may contains RoutingKey,CryptoKey,ExtraData

        auto keys_str = processed_uri_view.substr(0, pos);

        if (auto keys_tuple = parse_routing_crypto_keys(keys_str); keys_tuple) {
            auto [routing_key, crypto_key, extra] = *keys_tuple;

            uri_params.routing_key = std::move(routing_key);
            uri_params.crypto_key = std::move(crypto_key);
            uri_params.extra = std::move(extra);
            uri_path = processed_uri_view.substr(pos + 1);
        }
        else {
            // URI does not contain RoutingKey, CryptoKey and ExtraData, so
            // the first part of the URI separated by '/' might be a docname in
            // a KSK.
            uri_path = processed_uri_view;
        }
    }
    else {
        // No '/' found, it's possibly a KSK
        uri_path = processed_uri_view;
    }

    uri_params.meta_strings = parse_meta_strings(uri_path);

    return std::make_unique<Uri>(std::move(uri_params));

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

Uri_type Uri::parse_uri_type_str(std::string_view str)
{
    using enum keys::Uri_type;

    Uri_type uri_type{};

    auto uri_type_str = std::string(str);
    boost::algorithm::to_lower(uri_type_str);
    if (uri_type_str == "usk") { uri_type = usk; }
    else if (uri_type_str == "ssk") {
        uri_type = ssk;
    }
    else if (uri_type_str == "chk") {
        uri_type = chk;
    }
    else if (uri_type_str == "ksk") {
        uri_type = ksk;
    }
    else {
        throw exception::Malformed_uri{"Invalid URI: unknown key type"};
    }

    return uri_type;
}

std::optional<std::tuple<std::vector<std::byte>, std::vector<std::byte>,
                         std::vector<std::byte>>>
Uri::parse_routing_crypto_keys(const std::string_view keys_str)
{
    auto keys_str_copy = keys_str;

    std::optional<std::string_view> routing_key;
    std::optional<std::string_view> crypto_key;
    std::optional<std::string_view> extra;

    size_t comma_pos = std::string_view::npos;
    if (comma_pos = keys_str_copy.find(',');
        comma_pos < keys_str_copy.size()
        && comma_pos != std::string_view::npos) {
        routing_key = keys_str_copy.substr(0, comma_pos);
        keys_str_copy.remove_prefix(comma_pos + 1);
    }
    if (comma_pos = keys_str_copy.find(',');
        comma_pos < keys_str_copy.size()
        && comma_pos != std::string_view::npos) {
        crypto_key = keys_str_copy.substr(0, comma_pos);
        keys_str_copy.remove_prefix(comma_pos + 1);
    }
    if (!keys_str_copy.empty()) { extra = keys_str_copy; }

    using namespace support::base64;
    if (routing_key && crypto_key && extra) {
        // URI does contain RoutingKey, CryptoKey and ExtraData

        return std::tuple{decode_freenet(*routing_key),
                          decode_freenet(*crypto_key), decode_freenet(*extra)};
    }
    return std::nullopt;
}

std::vector<std::string> Uri::parse_meta_strings(std::string_view uri_path)
{
    std::vector<std::string> meta_strings;
    if (!uri_path.empty()) {
        size_t start = 0;
        size_t end = uri_path.find(uri_separator);

        if (end == std::string_view::npos) {
            // No '/' is found in the URI Path. So the whole URI Path is a meta
            // string
            meta_strings.push_back(url_decode(uri_path));
        }

        while (end != std::string_view::npos) {
            if (start < end) { // In case the first char is '/'
                try {
                    meta_strings.push_back(
                        url_decode(uri_path.substr(start, end - start)));
                }
                catch (const support::exception::Url_decode_error&) {
                    throw exception::Malformed_uri{
                        "Invalid URI: invalid meta string"};
                }
            }
            start = end + 1;
            end = uri_path.find(uri_separator, start);
        }
    }

    return meta_strings;
}

} // namespace keys
