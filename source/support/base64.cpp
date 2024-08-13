#include "libhyphanet/support/base64.h"

#include "libhyphanet/support.h"

#include <algorithm>
#include <array>
#include <cryptopp/algparam.h>
#include <cryptopp/argnames.h>
#include <cryptopp/base64.h> // NOLINT
#include <cryptopp/config_int.h>
#include <cryptopp/filters.h> // NOLINT
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/**
 * @brief Base64 encoding related functions.
 *
 * @details
 * Both Freenet specified Base64 and standard Base64 encoding/decoding are
 * implemented.
 *
 * Freenet specified Base64 encoding is modified Base64 with [slightly different
 * characters](#base64_alphabet_freenet) than usual, so it won't require
 * escaping when used in URIs. Also by default, the equals sign (=) padding is
 * not added.
 *
 */
namespace support::base64 {

namespace {
    std::array<CryptoPP::byte, 65>
    alphabet_str_to_bytes(std::string_view alphabet)
    {
        std::array<CryptoPP::byte, 65> alphabet_bytes{};
        std::ranges::copy(alphabet, alphabet_bytes.begin());

        return alphabet_bytes;
    }
} // namespace

std::string encode(
    const std::vector<std::byte>& bytes,
    bool equals_pad,
    std::string_view alphabet
)
{
    using namespace CryptoPP;

    Base64Encoder encoder;
    AlgorithmParameters params
        = MakeParameters(Name::InsertLineBreaks(), false);

    if (!equals_pad) { params = params(Name::Pad(), false); }

    std::array<CryptoPP::byte, 65> alphabet_bytes{};
    if (!alphabet.empty()) {
        alphabet_bytes = alphabet_str_to_bytes(alphabet);
        const byte* alphabet_ptr = alphabet_bytes.data();
        params
            = params(Name::EncodingLookupArray(), std::as_const(alphabet_ptr));
    }

    encoder.IsolatedInitialize(params);

    std::string encoded;
    const std::string decoded = util::bytes_to_str(bytes);

    encoder.Attach(new StringSink(encoded)); // NOLINT

    const StringSource ss(
        decoded,
        true,
        new Redirector(encoder) // Base64Encoder
    ); // StringSource

    return encoded;
}

std::vector<std::byte>
decode(std::string_view encoded, std::string_view alphabet)
{
    using namespace CryptoPP;

    Base64Decoder decoder;
    AlgorithmParameters params;

    std::array<int, 256> lookup{};
    if (!alphabet.empty()) {
        const auto alphabet_bytes = alphabet_str_to_bytes(alphabet);
        Base64Decoder::InitializeDecodingLookupArray(
            lookup.data(), alphabet_bytes.data(), 64, false
        );
        const int* lookup_ptr = lookup.data();
        params = params(Name::DecodingLookupArray(), lookup_ptr);
    }

    decoder.IsolatedInitialize(params);

    std::string decoded;
    const std::string encoded_str{encoded};

    decoder.Attach(new StringSink(decoded)); // NOLINT

    const StringSource ss(
        encoded_str,
        true, // NOLINT
        new Redirector(decoder) // Base64Decoder
    ); // StringSource

    return util::str_to_bytes(decoded);
}

} // namespace support::base64
