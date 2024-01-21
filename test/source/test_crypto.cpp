#include "crypto.cpp" // NOLINT
#include "libhyphanet/crypto.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/integer.h>
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
    using namespace CryptoPP;
    using namespace crypto::dsa;

    auto [priv_key_bytes, pub_key_bytes] = crypto::dsa::generate_keys();

    fmt::println("Private key bytes: {:02x}", fmt::join(priv_key_bytes, " "));

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

    DL_GroupParameters_DSA params;
    params.Initialize(group_big_a_params.p, group_big_a_params.q,
                      group_big_a_params.g);
    const Integer x{
        "7023799064111746470536234125360927524069493472142839802707671571"
        "6722926262045"};

    CryptoPP::DSA::PrivateKey priv_key;
    priv_key.Initialize(params, x);
    priv_key_bytes = priv_key_to_bytes(priv_key);

    // As bytes
    auto priv_key_mpi_bytes = priv_key_bytes_to_mpi_bytes(priv_key_bytes);
    fmt::println("Private key MPI bytes: {:02x}",
                 fmt::join(priv_key_mpi_bytes, " "));

    REQUIRE(
        priv_key_mpi_bytes
        == support::util::hex_to_bytes("0100009b494b3cfac60b09ba9f5f59bce5f0fc3"
                                       "c37b5722ddbf1e9c9fd5da3e063971d"));
}

TEST_CASE("SHA-256", "[library][crypto]")
{
    crypto::Sha256 hasher;

    const std::string message_1{"Yoda said, Do or do not. "};
    const std::string message_2{"There is no try."};

    hasher.update(support::util::str_to_bytes(message_1));
    hasher.update(message_2);

    auto digest = hasher.digest();
    fmt::println("SHA-256: {:02x}", fmt::join(digest, " "));

    auto bytes_to_verify
        = support::util::hex_to_bytes("F00E3F70A268FBA990296B32FF2B6CE7A07"
                                      "57F31EC3059B13D3DB1E60D9E885C");
    std::array<std::byte, 32> digest_to_verify{};
    std::ranges::copy(bytes_to_verify, digest_to_verify.begin());

    REQUIRE(digest == digest_to_verify);
}