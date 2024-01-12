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

namespace concepts {

    /**
     * @brief checks if the type T is an enumeration and if its underlying type
     * is int.
     */
    template<typename T> concept EnumWithInt
        = std::is_enum_v<T> && std::same_as<std::underlying_type_t<T>, int>;

    /**
     * @brief checks if the given type T is either char (underlying type of
     * std::string) or char8_t (underlying type of std::u8string).
     */
    template<typename T> concept CharOrChar8_t
        = std::is_same_v<T, char> || std::is_same_v<T, char8_t>;

    /**
     * @brief check if a given type R meets specific requirements to be
     * considered a range with an underlying type T.
     *
     * @tparam T the underlying type required for the range R
     * @tparam R the Range type
     */
    template<typename T, typename R>
    concept RangeWithUnderlyingType = requires(R range) {
        typename R::value_type; // The range has a value_type
        {
            std::begin(range)
        }
        -> std::same_as<typename R::iterator>; // The range has a begin iterator
        {
            std::end(range)
        }
        -> std::same_as<typename R::iterator>; // The range has an end iterator
        // The value_type of the range matches T
        requires std::same_as<typename R::value_type, T>;
    };
} // namespace concepts

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
    template<concepts::EnumWithInt E>
    bool compare_byte_enum(std::byte byte_value, E enum_value)
    {
        // Convert the enum class item to its underlying type using
        // std::to_underlying
        auto underlying_e = static_cast<int>(enum_value);
        // Convert the std::byte to an integer type using std::to_integer
        auto integer_b = std::to_integer<int>(byte_value);
        // Compare the converted values using the == operator
        return underlying_e == integer_b;
    }

    /**
     * @brief Checks if a value is within the range of a given range.
     *
     * @param val the value to check
     * @param arr the range to check against
     *
     * @return true if the value is within the range, false otherwise
     */
    template<typename T, typename R>
    requires concepts::RangeWithUnderlyingType<T, R>
    bool in_range(const T& val, const R& arr)
    {
        auto it = std::ranges::find(arr, val);
        return it != arr.end();
    }

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
    template<concepts::CharOrChar8_t T>
    std::vector<std::byte> basicstr_to_bytes(std::basic_string_view<T> str)
    {
        std::vector<std::byte> bytes;
        bytes.reserve(str.size());
        std::ranges::transform(str, std::back_inserter(bytes), [](char c) {
            return static_cast<std::byte>(c);
        });
        return bytes;
    }

    inline std::vector<std::byte> str_to_bytes(std::string_view str)
    {
        return basicstr_to_bytes(str);
    }

    inline std::vector<std::byte> u8str_to_bytes(std::u8string_view str)
    {
        return basicstr_to_bytes(str);
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
    template<concepts::CharOrChar8_t T>
    std::basic_string<T> bytes_to_basicstr(const std::vector<std::byte>& bytes)
    {
        std::basic_string<T> str;
        str.reserve(bytes.size());
        std::ranges::transform(bytes, std::back_inserter(str),
                               [](std::byte b) { return static_cast<T>(b); });
        return str;
    }

    inline std::string bytes_to_str(const std::vector<std::byte>& bytes)
    {
        return bytes_to_basicstr<char>(bytes);
    }

    inline std::u8string bytes_to_u8str(const std::vector<std::byte>& bytes)
    {
        return bytes_to_basicstr<char8_t>(bytes);
    }

    std::u8string str_to_u8str(std::string_view str);
    std::string u8str_to_str(std::u8string_view u8str);

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
