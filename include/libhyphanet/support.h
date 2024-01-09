#ifndef LIBHYPHANET_SUPPORT_H
#define LIBHYPHANET_SUPPORT_H

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <ranges>
#include <stdexcept>
#include <string>
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

    /**
     * @brief Converts a string to a vector of bytes.
     *
     * @param str the string to convert
     *
     * @return a vector of bytes representing the string
     */
    std::vector<std::byte> str_to_bytes(std::string_view str);

    /**
     * @brief Converts a vector of bytes to a string
     *
     * @param bytes the vector of bytes to convert
     * @return std::string the converted string
     */
    std::string bytes_to_str(const std::vector<std::byte>& bytes);

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
    std::string url_decode(std::string_view str, bool tolerant);
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
