#include "libhyphanet/crypto.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cryptopp/queue.h>
#include <cstddef>
#include <fmt/core.h>
#include <fmt/format.h>
#include <string>

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

    REQUIRE(encrypted == cipher);

    const std::array<std::byte, 32> decrypted
        = crypto::rijndael256_256_decrypt(key, cipher);

    REQUIRE(decrypted == plain);
}

TEST_CASE("DSA", "[library][crypto]")
{
    auto [priv_key_bytes, pub_key_bytes] = crypto::dsa::generate_keys();

    fmt::println(
        "Private key: {:02x}",
        fmt::join(crypto::dsa::priv_key_bytes_to_pkcs8(priv_key_bytes), " "));

    fmt::println(
        "Public key: {:02x}",
        fmt::join(crypto::dsa::pub_key_bytes_to_x509(pub_key_bytes), " "));

    const auto message = support::util::str_to_bytes("Hello, world!");
    const auto signature = crypto::dsa::sign(priv_key_bytes, message);
    fmt::println("Signature: {:02x}", fmt::join(signature, " "));

    REQUIRE(crypto::dsa::verify(pub_key_bytes, message, signature));
}