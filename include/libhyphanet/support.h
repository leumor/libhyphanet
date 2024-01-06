#ifndef BEAF81A1_E113_4CC0_AEB5_F56059EB9C35
#define BEAF81A1_E113_4CC0_AEB5_F56059EB9C35

#include <concepts>
#include <cstddef>
#include <type_traits>

namespace util {
template<typename T> concept EnumWithInt
    = std::is_enum_v<T> && std::same_as<std::underlying_type_t<T>, int>;

// A template function that compares a std::byte and an enum class item
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

#endif /* BEAF81A1_E113_4CC0_AEB5_F56059EB9C35 */
