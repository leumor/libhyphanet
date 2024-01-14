#include "libhyphanet/crypto.h"
#include "cppcrypto/block_cipher.h"
#include "cppcrypto/rijndael.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>

std::array<unsigned char, 32>
bytes_to_chars(const std::array<std::byte, 32>& bytes)
{
    std::array<unsigned char, 32> chars{};
    std::ranges::transform(bytes, std::begin(chars), [](std::byte b) {
        return static_cast<unsigned char>(b);
    });
    return chars;
}

std::array<std::byte, 32>
chars_to_bytes(const std::array<unsigned char, 32>& chars)
{
    std::array<std::byte, 32> bytes{};
    std::ranges::transform(chars, std::begin(bytes), [](unsigned char c) {
        return static_cast<std::byte>(c);
    });
    return bytes;
}

namespace crypto {
std::array<std::byte, 32>
rijndael256_256_encrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input)
{
    using namespace cppcrypto;
    auto rijndael = std::make_unique<rijndael256_256>();
    rijndael->init(bytes_to_chars(key).data(),
                   block_cipher::direction::encryption);

    std::array<unsigned char, 32> output{};
    rijndael->encrypt_block(bytes_to_chars(input).data(), output.data());

    return chars_to_bytes(output);
}
} // namespace crypto