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

template<concepts::CharOrChar8_t T>
std::string encode_str_freenet(std::basic_string_view<T> str, bool equals_pad)
{
    auto bytes = util::str_to_bytes(str);

    return encode(bytes, equals_pad, base64_alphabet_freenet);
}

template<concepts::CharOrChar8_t T>
std::string encode_str_standard(std::basic_string_view<T> str)
{
    auto bytes = util::str_to_bytes(str);

    return encode(bytes, true, std::nullopt);
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

inline std::string decode_str_freenet(std::string_view str)
{
    auto decoded = decode_freenet(str);

    return util::bytes_to_str<char>(decoded);
}

inline std::string decode_str_standard(std::string_view str)
{
    auto decoded = decode_standard(str);

    return util::bytes_to_str<char>(decoded);
}

} // namespace support::base64

#endif /* LIBHYPHANET_SUPPORT_BASE64_H */
