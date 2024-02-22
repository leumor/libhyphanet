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
 * @details
 * This function only does the padding that's normal in Base64
 * if the equals_pad is set to true. This is because Base64 requires that the
 * length of the encoded text be a multiple of four characters, padded with '='.
 * Without the 'true' equals_pad, we don't add these '=' characters.
 *
 * @param bytes The bytes to be encoded.
 * @param equals_pad Whether to pad the encoded string with equals signs (=).
 * @param alphabet An optional string_view representing the custom alphabet to
 * be used for encoding.
 *
 * @return The encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT std::string
encode(const std::vector<std::byte>& bytes, bool equals_pad,
       std::optional<std::string_view> alphabet);

/**
 * @brief Encodes the given bytes using Base64 encoding with [Freenet specific
 * base64 alphabet](#base64_alphabet_freenet).
 *
 * @details
 * This is modified Base64 with slightly different characters than
 * usual, so it won't require escaping when used in URLs.
 *
 * The encoded string won't be padded with equals signs (=).
 *
 * @param bytes the bytes to be encoded.
 *
 * @return the encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_freenet(const std::vector<std::byte>& bytes)
{
    return encode(bytes, false, base64_alphabet_freenet);
}

/**
 * @brief Encodes the given bytes using the standard Base64 encoding.
 *
 * @param bytes the bytes to be encoded.
 *
 * @return The encoded string.
 * encoding.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_standard(const std::vector<std::byte>& bytes)
{
    return encode(bytes, true, std::nullopt);
}

/**
 * @brief Encodes a basic string into a base64 string using the [Freenet
 * specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @tparam T The type of the basic string. Either char for std::string or
 * char8_t for std::u8string
 *
 * @param str The basic string to be encoded.
 * @param equals_pad Whether to pad the encoded string with equals signs (=).
 *
 * @return The encoded base64 string.
 */
template<concepts::CharOrChar8_t T> [[nodiscard]] LIBHYPHANET_EXPORT std::string
encode_basicstr_freenet(std::basic_string_view<T> str, bool equals_pad)
{
    auto bytes = util::basicstr_to_bytes(str);

    return encode(bytes, equals_pad, base64_alphabet_freenet);
}

/**
 * @brief Encodes a string into a base64 string using the [Freenet specific
 * base64 alphabet](#base64_alphabet_freenet).
 *
 * @param str The string to be encoded.
 * @param equals_pad Whether to pad the encoded string with equals signs (=).
 *
 * @return The encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_str_freenet(std::string_view str, bool equals_pad = false)
{
    return encode_basicstr_freenet(str, equals_pad);
}

/**
 * @brief Encodes a std::u8string into a base64 string using the [Freenet
 * specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @param str The std::u8string to be encoded.
 * @param equals_pad Whether to pad the encoded string with equals signs (=).
 *
 * @return The encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_u8str_freenet(std::u8string_view str, bool equals_pad = false)
{
    return encode_basicstr_freenet(str, equals_pad);
}

/**
 * @brief Encodes a basic string using the standard Base64 encoding.
 *
 * @tparam T The type of the basic string. Either char for std::string or
 * char8_t for std::u8string
 *
 * @param str The basic string to be encoded.
 *
 * @return The encoded string.
 */
template<concepts::CharOrChar8_t T> [[nodiscard]] LIBHYPHANET_EXPORT std::string
encode_basicstr_standard(std::basic_string_view<T> str)
{
    auto bytes = util::basicstr_to_bytes(str);

    return encode(bytes, true, std::nullopt);
}

/**
 * @brief Encodes a string using the standard Base64 encoding.
 *
 * @param str The string to be encoded.
 *
 * @return The encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_str_standard(std::string_view str)
{
    return encode_basicstr_standard(str);
}

/**
 * @brief Encodes a std::u8string using the standard Base64 encoding.
 *
 * @param str The string to be encoded.
 *
 * @return The encoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
encode_u8str_standard(std::u8string_view str)
{
    return encode_basicstr_standard(str);
}

/**
 * @brief Decodes the given encoded string using the Base64 encoding.
 *
 * @param encoded The string to be decoded.
 * @param alphabet An optional string_view representing the custom alphabet to
 * be used for encoding.
 *
 * @return The decoded bytes.
 */
[[nodiscard]] LIBHYPHANET_EXPORT std::vector<std::byte>
decode(std::string_view encoded, std::optional<std::string_view> alphabet);

/**
 * @brief Decodes the given string using the Base64 encoding with the [Freenet
 * specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded bytes.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::vector<std::byte>
decode_freenet(std::string_view encoded)
{
    return decode(encoded, base64_alphabet_freenet);
}

/**
 * @brief Decodes the given string using the standard Base64 encoding.
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded bytes.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::vector<std::byte>
decode_standard(std::string_view encoded)
{
    return decode(encoded, std::nullopt);
}

/**
 * @brief Decodes the given encoded string using the Base64 encoding with
 * the [Freenet specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @tparam T The type of the returned basic string. Either char for std::string
 * or char8_t for std::u8string
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded basic string.
 */
template<concepts::CharOrChar8_t T> LIBHYPHANET_EXPORT
    [[nodiscard]] std::basic_string<T>
    decode_basicstr_freenet(std::string_view encoded)
{
    auto decoded = decode_freenet(encoded);

    return util::bytes_to_basicstr<T>(decoded);
}

/**
 * @brief Decodes the given string using the Base64 encoding with the
 * [Freenet specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
decode_str_freenet(std::string_view encoded)
{
    return decode_basicstr_freenet<char>(encoded);
}

/**
 * @brief Decodes the given string using the Base64 encoding with the
 * [Freenet specific base64 alphabet](#base64_alphabet_freenet).
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded std::u8string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::u8string
decode_u8str_freenet(std::string_view encoded)
{
    return decode_basicstr_freenet<char8_t>(encoded);
}

/**
 * @brief Decodes the given encoded string using the standard Base64 encoding.
 *
 * @tparam T The type of the returned basic string. Either char for std::string
 * or char8_t for std::u8string
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded basic string.
 */
template<concepts::CharOrChar8_t T> LIBHYPHANET_EXPORT
    [[nodiscard]] std::basic_string<T>
    decode_basicstr_standard(std::string_view encoded)
{
    auto decoded = decode_standard(encoded);

    return util::bytes_to_basicstr<T>(decoded);
}

/**
 * @brief Decodes the given string using the standard Base64 encoding.
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::string
decode_str_standard(std::string_view encoded)
{
    return decode_basicstr_standard<char>(encoded);
}

/**
 * @brief Decodes the given string using the standard Base64 encoding.
 *
 * @param encoded The string to be decoded.
 *
 * @return The decoded std::u8string.
 */
[[nodiscard]] LIBHYPHANET_EXPORT inline std::u8string
decode_u8str_standard(std::string_view encoded)
{
    return decode_basicstr_standard<char8_t>(encoded);
}

} // namespace support::base64

#endif /* LIBHYPHANET_SUPPORT_BASE64_H */
