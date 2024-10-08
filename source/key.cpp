#include "libhyphanet/key.h"

#include "libhyphanet/support.h"
#include "libhyphanet/support/base64.h"

#include <array>
#include <boost/algorithm/string/case_conv.hpp>
#include <cstddef>
#include <gsl/assert>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace support::util;
using namespace support::url;

namespace key {

Uri::Uri(Uri_params url_params)
    : uri_type_{url_params.uri_type},
      routing_key_{std::move(url_params.routing_key)},
      crypto_key_{url_params.crypto_key},
      extra_{std::move(url_params.extra)},
      meta_strings_{std::move(url_params.meta_strings)}
{
    // routing_key_ and crypto_key_ and extra_ are all existent or non-existent
    Expects(
        (!routing_key_.empty() && crypto_key_ && !extra_.empty())
        || (routing_key_.empty() && !crypto_key_ && extra_.empty())
    );
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
            processed_uri = support::url::url_decode(uri);
        }
        catch (const Url_decode_error&) {
            throw exception::Malformed_uri{
                "Invalid URI: no @ or /, or @ or / is escaped but there are "
                "invalid escapes"
            };
        }
    }

    // Strip http(s):// and (web+|ext+)(freenet|hyphanet|hypha): prefix
    static const std::regex re{
        "^(https?://[^/]+/+)?(((ext|web)\\+)?(freenet|hyphanet|hypha):)?"
    };

    const auto processed_uri_const = std::regex_replace(
        processed_uri, re, "", std::regex_constants::format_first_only
    );
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
            uri_params.crypto_key = crypto_key;
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
}

Uri_type Uri::parse_uri_type_str(std::string_view str)
{
    using enum key::Uri_type;

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

std::optional<std::tuple<
    std::vector<std::byte>,
    std::optional<std::array<std::byte, crypto_key_length>>,
    std::vector<std::byte>>>
Uri::parse_routing_crypto_keys(const std::string_view keys_str)
{
    auto keys_str_copy = keys_str;

    std::string_view routing_key;
    std::string_view crypto_key;
    std::string_view extra;

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
    if (!routing_key.empty() && !crypto_key.empty() && !extra.empty()) {
        // URI does contain RoutingKey, CryptoKey and ExtraData
        auto crypto_key_bytes = decode_freenet(crypto_key);
        if (crypto_key_bytes.size() != crypto_key_length) {
            throw exception::Malformed_uri{"Invalid URI: invalid crypto key"};
        }

        return std::tuple{
            decode_freenet(routing_key),
            vector_to_array<std::byte, crypto_key_length>(crypto_key_bytes),
            decode_freenet(extra)
        };
    }
    return std::nullopt;
}

std::vector<std::string> Uri::parse_meta_strings(std::string_view uri_path)
{
    std::vector<std::string> meta_strings;

    if (uri_path.empty()) { return meta_strings; }

    size_t start = 0;
    size_t end = 0;

    while (true) {
        // Skip all consecutive '/'
        while (uri_path.at(start) == uri_separator) { start += 1; }

        // If we skipped any consecutive '/', add one empty string
        // As SSK@blah,blah,blah//filename is allowed with empty docname
        if (start > 1 && start < uri_path.size()
            && uri_path.at(start - 1) == uri_separator
            && uri_path.at(start - 2) == uri_separator) {
            append_meta_string(meta_strings, "");
        }

        end = uri_path.find(uri_separator, start);

        if (end != std::string_view::npos) {
            append_meta_string(
                meta_strings, uri_path.substr(start, end - start)
            );

            start = end + 1;
        }
        else {
            if (start < uri_path.size()) {
                // Last part of the URI Path
                append_meta_string(
                    meta_strings,
                    uri_path.substr(start, uri_path.size() - start)
                );
            }
            break;
        }
    }

    return meta_strings;
}

std::string Uri::to_string(bool prefix, bool pure_ascii) const
{
    std::stringstream ss;

    if (prefix) { ss << "hypha:"; }

    ss << uri_type_to_string.at(uri_type_) << '@';

    if (!routing_key_.empty() && crypto_key_ && !extra_.empty()) {
        ss << support::base64::encode_freenet(routing_key_) << ','
           << support::base64::encode_freenet(array_to_vector(*crypto_key_))
           << ',' << support::base64::encode_freenet(extra_) << '/';
    }

    for (const std::string& meta_string: meta_strings_) {
        ss << url_encode(meta_string, pure_ascii, "/") << '/';
    }

    std::string ret{ss.str()};
    if (ret.back() == '/') {
        ret.pop_back(); // Remove last "/"
    }
    return ret;
}

std::string Uri::to_ascii_string() const
{
    return to_string(true, true);
}

void Uri::append_meta_strings(
    const std::vector<std::string>& additional_meta_strings
)
{
    meta_strings_.insert(
        meta_strings_.end(),
        additional_meta_strings.begin(),
        additional_meta_strings.end()
    );
}

void Uri::append_meta_string(std::string_view additional_meta_string)
{
    append_meta_string(meta_strings_, additional_meta_string);
}

void Uri::append_meta_string(
    std::vector<std::string>& meta_strings,
    std::string_view additional_meta_string
)
{
    if (additional_meta_string != std::string(1, uri_separator)) {
        try {
            meta_strings.push_back(url_decode(additional_meta_string));
        }
        catch (const Url_decode_error&) {
            throw exception::Malformed_uri{"Invalid URI: invalid meta string"};
        }
    }
}
} // namespace key
