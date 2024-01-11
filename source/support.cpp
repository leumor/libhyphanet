#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <gsl/util>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace support {
namespace util {
    template<typename T>
    bool in_range(const T& val, const std::ranges::range auto& arr)
    {
        auto it = std::ranges::find(arr, val);
        return it != arr.end();
    }

    template<typename EnumWithInt>
    bool compare_byte_enum(std::byte byte_value, EnumWithInt enum_value)
    {
        // Convert the enum class item to its underlying type using
        // std::to_underlying
        auto underlying_e = static_cast<int>(enum_value);
        // Convert the std::byte to an integer type using std::to_integer
        auto integer_b = std::to_integer<int>(byte_value);
        // Compare the converted values using the == operator
        return underlying_e == integer_b;
    }

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
                        auto buf = str_to_bytes<char>('%' + hex_str);
                        decoded_bytes.insert(decoded_bytes.end(), buf.begin(),
                                             buf.end());
                        continue;
                    }

                    throw Url_decode_error(ex.what());
                }
            }
            else {
                decoded_bytes.push_back(static_cast<std::byte>(*iter));
            }
            ++iter;
        }

        return bytes_to_str<char>(decoded_bytes);
    }
} // namespace util
} // namespace support