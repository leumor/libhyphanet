#ifndef LIBHYPHANET_SUPPORT_H
#define LIBHYPHANET_SUPPORT_H

#include <concepts>
#include <cstddef>
#include <type_traits>

namespace support {

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
     * @return bool true if the two underlying values are equal
     */
    template<typename Enum>
    bool compare_byte_enum(std::byte byte_value, Enum enum_value)
    {
        // Convert the enum class item to its underlying type using
        // std::to_underlying
        auto underlying_e = static_cast<int>(enum_value);
        // Convert the std::byte to an integer type using std::to_integer
        auto integer_b = std::to_integer<int>(byte_value);
        // Compare the converted values using the == operator
        return underlying_e == integer_b;
    }
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
