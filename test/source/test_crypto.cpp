#include "libhyphanet/crypto.h"
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <iostream>

std::array<std::byte, 32> chars_to_bytes(const std::array<char, 32>& chars)
{
    std::array<std::byte, 32> bytes{};
    std::ranges::transform(chars, std::begin(bytes),
                           [](char c) { return static_cast<std::byte>(c); });
    return bytes;
}

TEST_CASE("rijndael256_256", "[library][crypto]")
{
    const std::array<std::byte, 32> plain = chars_to_bytes({
        1,   35,   69,  103, -119, -85, -51,  -17, 17,  35,   69,
        103, -119, -85, -51, -17,  33,  35,   69,  103, -119, -85,
        -51, -17,  49,  35,  69,   103, -119, -85, -51, -17,
    });
    const std::array<std::byte, 32> key = chars_to_bytes({
        -34, -83,  -66, -17, -54, -2,  -70, -66, 1,   35,  69,
        103, -119, -85, -51, -17, -54, -2,  -70, -66, -34, -83,
        -66, -17,  -54, -2,  -70, -66, 1,   35,  69,  103,
    });
    const std::array<std::byte, 32> cipher = chars_to_bytes({
        111, -53, -58, -113, -55, 56,   -27, -11, -89, -62,  77,
        116, 34,  -12, -75,  -15, 83,   37,  123, 111, -75,  62,
        11,  -54, 38,  119,  4,   -105, -35, 101, 7,   -116,
    });

    const std::array<std::byte, 32> encrypted
        = crypto::rijndael256_256_encrypt(key, plain);

    for (std::size_t i = 0; i < 32; ++i) {
        std::cout << std::hex << static_cast<int>(encrypted.at(i)) << " ";
    }

    REQUIRE(encrypted == cipher);
}