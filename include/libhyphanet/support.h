#ifndef LIBHYPHANET_SUPPORT_H
#define LIBHYPHANET_SUPPORT_H

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unicode/unistr.h>
#include <vector>

namespace support {

namespace exception {
    /**
     * @brief An exception class for url decode errors
     *
     */
    class Url_decode_error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };
} // namespace exception

namespace util {
    // trim from start (in place)
    static inline void ltrim(std::string_view& s,
                             std::string_view chars = " \t\r\v\n")
    {
        s.remove_prefix(std::min(s.find_first_not_of(chars), s.size()));
    }

    // trim from end (in place)
    static inline void rtrim(std::string_view& s,
                             std::string_view chars = " \t\r\v\n")
    {
        s.remove_suffix(
            std::min(s.size() - s.find_last_not_of(chars) - 1, s.size()));
    }

    // trim from both ends (in place)
    static inline void trim(std::string_view& s,
                            std::string_view chars = " \t\r\v\n")
    {
        ltrim(s, chars);
        rtrim(s, chars);
    }

    // trim from start (copying)
    static inline std::string_view
    ltrim_copy(std::string_view s, std::string_view chars = " \t\r\v\n")
    {
        ltrim(s, chars);
        return s;
    }

    // trim from end (copying)
    static inline std::string_view
    rtrim_copy(std::string_view s, std::string_view chars = " \t\r\v\n")
    {
        rtrim(s, chars);
        return s;
    }

    // trim from both ends (copying)
    static inline std::string_view
    trim_copy(std::string_view s, std::string_view chars = " \t\r\v\n")
    {
        trim(s, chars);
        return s;
    }

    template<typename T> concept EnumWithInt
        = std::is_enum_v<T> && std::same_as<std::underlying_type_t<T>, int>;

    /**
     * @brief A template function that compares a std::byte and an enum class
     * item
     *
     * @tparam Enum the enum class type
     * @param byte_value the std::byte value
     * @param enum_value the enum class item
     *
     * @return bool true if the two underlying values are equal
     */
    template<typename EnumWithInt>
    bool compare_byte_enum(std::byte byte_value, EnumWithInt enum_value);

    /**
     * @brief Checks if a value is within the range of a given range.
     *
     * @param val the value to check
     * @param arr the range to check against
     *
     * @return true if the value is within the range, false otherwise
     */
    template<typename T>
    bool in_range(const T& val, const std::ranges::range auto& arr);

    template<typename T> concept CharOrChar8_t
        = std::is_same_v<T, char> || std::is_same_v<T, char8_t>;

    /**
     * @brief Converts a string to a vector of bytes.
     *
     * @tparam T either char for std::string_view or char8_t for
     * std::u8string_view
     *
     * @param str the string to convert
     *
     * @return a vector of bytes representing the string
     */
    template<CharOrChar8_t T>
    std::vector<std::byte> str_to_bytes(std::basic_string_view<T> str)
    {
        std::vector<std::byte> bytes;
        bytes.reserve(str.size());
        std::ranges::transform(str, std::back_inserter(bytes), [](char c) {
            return static_cast<std::byte>(c);
        });
        return bytes;
    }

    /**
     * @brief Converts a vector of bytes to a string
     *
     * @tparam T either char for std::string or char8_t for
     * std::u8string
     *
     * @param bytes the vector of bytes to convert
     * @return std::string the converted string
     */
    template<CharOrChar8_t T>
    std::basic_string<T> bytes_to_str(const std::vector<std::byte>& bytes)
    {
        std::string str;
        str.reserve(bytes.size());
        std::ranges::transform(bytes, std::back_inserter(str), [](std::byte b) {
            return static_cast<char>(b);
        });
        return str;
    }

    std::vector<std::byte> u8str_to_bytes(std::u8string_view str);

    /**
     * @brief Decodes an freenet specific URL encoded string
     *
     * @param str String to be translated.
     * @param tolerant If true, be tolerant of bogus escapes; bogus escapes
     * are treated as just plain characters. Not recommended; a hack to
     * allow users to paste in URLs containing %'s.
     *
     * @return std::string the translated String.
     */
    std::string url_decode(std::string_view str, bool tolerant = false);
} // namespace util

namespace compressor {
    enum class Compress_type : short {
        gzip = 0,
        bzip2 = 1,
        lzma = 2,
        lzma_new = 3
    };
} // namespace compressor

} // namespace support

#endif /* LIBHYPHANET_SUPPORT_H */
