#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdlib>
#include <fmt/core.h>
#include <gsl/util>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unicode/schriter.h>
#include <unicode/uchar.h>
#include <unicode/unistr.h>
#include <unicode/urename.h>
#include <vector>

namespace support {
namespace util {
    std::u8string str_to_u8str(std::string_view str)
    {
        std::u8string u8str;
        u8str.reserve(str.size());
        std::ranges::transform(str, std::back_inserter(u8str), [](char c) {
            return std::bit_cast<char8_t>(c);
        });

        return u8str;
    }

    std::string u8str_to_str(std::u8string_view u8str)
    {
        std::string str;
        str.reserve(u8str.size());
        std::ranges::transform(u8str, std::back_inserter(str), [](char8_t c) {
            return std::bit_cast<char>(c);
        });

        return str;
    }

    std::array<unsigned char, 32>
    bytes_to_chars(const std::array<std::byte, 32>& bytes)
    {
        std::array<unsigned char, 32> chars{};
        std::ranges::transform(bytes, std::begin(chars), [](std::byte b) {
            return std::bit_cast<unsigned char>(b);
        });
        return chars;
    }

    std::array<std::byte, 32>
    chars_to_bytes(const std::array<unsigned char, 32>& chars)
    {
        std::array<std::byte, 32> bytes{};
        std::ranges::transform(chars, std::begin(bytes), [](unsigned char c) {
            return std::bit_cast<std::byte>(c);
        });
        return bytes;
    }

    std::vector<std::byte> hex_to_bytes(std::string_view hex)
    {
        std::vector<std::byte> bytes;

        for (unsigned int i = 0; i < hex.length(); i += 2) {
            auto byte_string = hex.substr(i, 2);
            auto byte = static_cast<std::byte>(
                std::stoi(std::string{byte_string}, nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    }

    double key_digest_as_normalized_double(const std::vector<std::byte>& digest)
    {
        long as_long = std::abs(field::bytes_to_integer<long>(digest));

        if (as_long == std::numeric_limits<long>::min()) {
            as_long = std::numeric_limits<long>::max();
        }

        return static_cast<double>(as_long)
               / static_cast<double>(std::numeric_limits<long>::max());
    }

} // namespace util
namespace url {

    std::string url_decode(std::string_view str, bool tolerant)
    {
        if (str.empty()) { return std::string{}; }

        std::vector<std::byte> decoded_bytes;
        bool has_decoded_something{false};

        auto iter{std::cbegin(str)};
        while (iter != std::cend(str)) {
            if (*iter == '%') {
                if (std::distance(iter, std::cend(str)) < 3) {
                    throw Url_decode_error(
                        "There should be at least 2 characters after '%'");
                }

                std::array<char, 2> hex_chars{*(++iter), *(++iter)};
                auto hex_str = std::string{hex_chars.begin(), hex_chars.end()};
                try {
                    const int hex_val = std::stoi(hex_str, nullptr, 16);
                    if (hex_val == 0) {
                        throw Url_decode_error("Can't decode %00");
                    }
                    // hex_val should always fit in a byte as it's converted
                    // to a two chars hex string
                    decoded_bytes.push_back(
                        gsl::narrow_cast<std::byte>(hex_val));

                    has_decoded_something = true;
                }
                catch (std::invalid_argument const& ex) {
                    // Not encoded?
                    if (tolerant && !has_decoded_something) {
                        auto buf = util::str_to_bytes('%' + hex_str);
                        decoded_bytes.insert(decoded_bytes.end(), buf.begin(),
                                             buf.end());
                        ++iter;
                        continue;
                    }

                    throw Url_decode_error(ex.what());
                }
            }
            else {
                decoded_bytes.push_back(std::bit_cast<std::byte>(*iter));
            }
            ++iter;
        }

        return util::bytes_to_str(decoded_bytes);
    }

    std::string url_encode(std::string_view uri, bool ascii,
                           std::string_view force,
                           std::string_view extra_safe_chars)
    {
        static const auto safe_url_characters_uni
            = icu::UnicodeString::fromUTF8(safe_url_characters);
        auto extra_safe_chars_unicode
            = icu::UnicodeString::fromUTF8(extra_safe_chars);
        auto force_unicode = icu::UnicodeString::fromUTF8(force);

        std::stringstream ss;

        auto uri_unicode = icu::UnicodeString::fromUTF8(uri);
        icu::StringCharacterIterator iter{uri_unicode};

        for (auto c = iter.first32(); static_cast<bool>(iter.hasNext());
             c = iter.next32()) {
            std::string c_utf8;
            icu::UnicodeString{c}.toUTF8String(c_utf8);

            auto char_type = u_charType(c);

            if ((safe_url_characters_uni.indexOf(c) >= 0
                 || (!ascii && c >= 128 && char_type != U_UNASSIGNED
                     && char_type != U_CONTROL_CHAR && !u_isUWhiteSpace(c))
                 || extra_safe_chars_unicode.indexOf(c) >= 0)
                && (force.empty() || force_unicode.indexOf(c) < 0)) {
                ss << c_utf8;
            }
            else {
                for (const auto& b: c_utf8) {
                    ss << fmt::format("%{:02x}",
                                      std::bit_cast<unsigned char>(b));
                }
            }
        }

        return ss.str();
    }
} // namespace url

} // namespace support