#ifndef LIBHYPHANET_SUPPORT_BASE64_H
#define LIBHYPHANET_SUPPORT_BASE64_H

#include "libhyphanet/support.h"
#include <cryptopp/config_int.h>
#include <optional>
#include <string_view>
#include <vector>
namespace support::base64 {

/**
 * @brief Freenet specific base64 alphabet
 */
static const std::string base64_alphabet_freenet{
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012"
    "3456789~-"};

/**
 * @brief Encode bytes using Base64 encoding.
 *
 * @param bytes The bytes to be encoded.
 * @param equals_pad Whether to pad the encoded string with equals signs (=).
 * @param alphabet An optional string_view representing the custom alphabet to
 * be used for encoding.
 *
 * @return The encoded string.
 */
std::string encode(const std::vector<std::byte>& bytes, bool equals_pad,
                   std::optional<std::string_view> alphabet);

inline std::string encode_freenet(const std::vector<std::byte>& bytes)
{
    return encode(bytes, false, base64_alphabet_freenet);
}

inline std::string encode_standard(const std::vector<std::byte>& bytes)
{
    return encode(bytes, true, std::nullopt);
}

template<concepts::CharOrChar8_t T> std::string
encode_basicstr_freenet(std::basic_string_view<T> str, bool equals_pad)
{
    auto bytes = util::basicstr_to_bytes(str);

    return encode(bytes, equals_pad, base64_alphabet_freenet);
}
inline std::string encode_str_freenet(std::string_view str,
                                      bool equals_pad = false)
{
    return encode_basicstr_freenet(str, equals_pad);
}
inline std::string encode_u8str_freenet(std::u8string_view str,
                                        bool equals_pad = false)
{
    return encode_basicstr_freenet(str, equals_pad);
}

template<concepts::CharOrChar8_t T>
std::string encode_basicstr_standard(std::basic_string_view<T> str)
{
    auto bytes = util::basicstr_to_bytes(str);

    return encode(bytes, true, std::nullopt);
}
inline std::string encode_str_standard(std::string_view str)
{
    return encode_basicstr_standard(str);
}
inline std::string encode_u8str_standard(std::u8string_view str)
{
    return encode_basicstr_standard(str);
}

std::vector<std::byte> decode(std::string_view encoded,
                              std::optional<std::string_view> alphabet);

inline std::vector<std::byte> decode_freenet(std::string_view encoded)
{
    return decode(encoded, base64_alphabet_freenet);
}

inline std::vector<std::byte> decode_standard(std::string_view encoded)
{
    return decode(encoded, std::nullopt);
}

template<concepts::CharOrChar8_t T>
std::basic_string<T> decode_basicstr_freenet(std::string_view encoded)
{
    auto decoded = decode_freenet(encoded);

    return util::bytes_to_basicstr<T>(decoded);
}
inline std::string decode_str_freenet(std::string_view encoded)
{
    return decode_basicstr_freenet<char>(encoded);
}
inline std::u8string decode_u8str_freenet(std::string_view encoded)
{
    return decode_basicstr_freenet<char8_t>(encoded);
}

template<concepts::CharOrChar8_t T>
std::basic_string<T> decode_basicstr_standard(std::string_view encoded)
{
    auto decoded = decode_standard(encoded);

    return util::bytes_to_basicstr<T>(decoded);
}
inline std::string decode_str_standard(std::string_view encoded)
{
    return decode_basicstr_standard<char>(encoded);
}
inline std::u8string decode_u8str_standard(std::string_view encoded)
{
    return decode_basicstr_standard<char8_t>(encoded);
}

} // namespace support::base64

#endif /* LIBHYPHANET_SUPPORT_BASE64_H */
