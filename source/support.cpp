#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <gsl/util>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace support {
namespace util {
    std::string url_decode(std::string_view str, bool tolerant)
    {
        using namespace exception;

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
                    // hex_val should always fit in a byte as it's converted to
                    // a two chars hex string
                    decoded_bytes.push_back(
                        gsl::narrow_cast<std::byte>(hex_val));

                    has_decoded_something = true;
                }
                catch (std::invalid_argument const& ex) {
                    // Not encoded?
                    if (tolerant && !has_decoded_something) {
                        auto buf = str_to_bytes('%' + hex_str);
                        decoded_bytes.insert(decoded_bytes.end(), buf.begin(),
                                             buf.end());
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

        return bytes_to_str(decoded_bytes);
    }

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

} // namespace util
} // namespace support