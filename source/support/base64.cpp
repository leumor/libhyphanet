#include "libhyphanet/support/base64.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <cryptopp/algparam.h>
#include <cryptopp/argnames.h>
#include <cryptopp/base64.h>
#include <cryptopp/config_int.h>
#include <cryptopp/filters.h>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support::base64 {
std::string encode(const std::vector<std::byte>& bytes, bool equals_pad,
                   std::optional<std::string_view> alphabet)
{
    using namespace CryptoPP;

    Base64Encoder encoder;
    AlgorithmParameters params
        = MakeParameters(Name::InsertLineBreaks(), false);

    if (!equals_pad) { params = params(Name::Pad(), false); }

    if (alphabet) {
        std::array<CryptoPP::byte, 65> alphabet_bytes{};
        std::ranges::copy(*alphabet, alphabet_bytes.begin());

        const CryptoPP::byte* alphabet_bytes_ptr = alphabet_bytes.data();

        params = params(Name::EncodingLookupArray(), alphabet_bytes_ptr);
    }

    encoder.IsolatedInitialize(params);

    std::string encoded;
    const std::string decoded = util::bytes_to_str<char>(bytes);

    encoder.Attach(new StringSink(encoded)); // NOLINT

    const StringSource ss(decoded, true,
                          new Redirector(encoder) // Base64Encoder
    ); // StringSource

    return encoded;
}

} // namespace support::base64