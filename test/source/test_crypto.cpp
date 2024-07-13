#include "crypto.cpp" // NOLINT
#include "libhyphanet/crypto.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <boost/multiprecision/fwd.hpp>
#include <boost/multiprecision/gmp.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cryptopp/config_int.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/integer.h>
#include <cstddef>
#include <fmt/core.h>
#include <fmt/format.h>
#include <gmp.h>
#include <string>
#include <vector>

std::array<std::byte, 32>
chars_to_bytes(const std::array<signed char, 32>& chars)
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

    auto pfcb_256_encrypt_key = support::util::vector_to_array<std::byte, 32>(
        support::util::hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c"
                                    "073b6108d72d9810a30914dff4"));
    auto pfcb_256_encrypt_iv = support::util::vector_to_array<
        std::byte, 32>(support::util::hex_to_bytes(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

    auto pcfb_256_encrypt_plaintext = support::util::hex_to_bytes(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c"
        "46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

    auto pcfb_256_encrypt_ciphertext = support::util::hex_to_bytes(
        "c964b00326e216214f1a68f5b08726081b403c92fe02898664a81f5bbbbf8341fc1d04"
        "b2c1addfb826cca1eab68131272751b9d6cd536f78059b10b4867dbbd9");

    auto cipher_text = crypto::rijndael256_256_pcfb_encrypt(
        pfcb_256_encrypt_key, pfcb_256_encrypt_iv, pcfb_256_encrypt_plaintext);

    fmt::println("PCFB 256 Cipher text: {:02x}", fmt::join(cipher_text, " "));

    REQUIRE(cipher_text == pcfb_256_encrypt_ciphertext);

    auto plain_text = crypto::rijndael256_256_pcfb_decrypt(
        pfcb_256_encrypt_key, pfcb_256_encrypt_iv, cipher_text);

    fmt::println("PCFB 256 Plain text: {:02x}", fmt::join(plain_text, " "));

    REQUIRE(plain_text == pcfb_256_encrypt_plaintext);
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

TEST_CASE("Boost::multiprecision::mpz_int to CryptoPP::Integer conversion",
          "[library][crypto]")
{
    const CryptoPP::Integer a{"12345"};
    boost::multiprecision::mpz_int b{"12345"};

    auto result_boost = crypto::cryptopp_integer_to_mpz_int(a);
    REQUIRE(result_boost == b);

    auto result_cryptopp = crypto::mpz_int_to_cryptopp_integer(b);
    REQUIRE(result_cryptopp == a);
}