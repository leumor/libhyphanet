#include "libhyphanet/crypto.h"
#include "cppcrypto/block_cipher.h"
#include "cppcrypto/rijndael.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <bit>
#include <cryptopp/config_int.h>
#include <cryptopp/filters.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cstddef>
#include <fmt/core.h>
#include <fmt/format.h>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace crypto {
std::array<std::byte, 32>
rijndael256_256_encrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input)
{
    using namespace cppcrypto;
    using namespace support::util;

    auto rijndael = std::make_unique<rijndael256_256>();
    rijndael->init(bytes_to_chars(key).data(),
                   block_cipher::direction::encryption);

    std::array<unsigned char, 32> output{};
    rijndael->encrypt_block(bytes_to_chars(input).data(), output.data());

    return chars_to_bytes(output);
}

std::array<std::byte, 32>
rijndael256_256_decrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input)
{
    using namespace cppcrypto;
    using namespace support::util;

    auto rijndael = std::make_unique<rijndael256_256>();
    rijndael->init(bytes_to_chars(key).data(),
                   block_cipher::direction::decryption);

    std::array<unsigned char, 32> output{};
    rijndael->decrypt_block(bytes_to_chars(input).data(), output.data());

    return chars_to_bytes(output);
}

namespace {
    std::vector<std::byte>
    cryptoppbytes_to_bytes(const std::vector<CryptoPP::byte>& cryptopp_bytes)
    {
        std::vector<std::byte> std_bytes;
        std_bytes.reserve(cryptopp_bytes.size());

        std::ranges::transform(
            cryptopp_bytes, std::back_inserter(std_bytes),
            [](CryptoPP::byte b) { return std::bit_cast<std::byte>(b); });
        return std_bytes;
    }

    std::vector<CryptoPP::byte>
    bytes_to_cryptoppbytes(const std::vector<std::byte>& bytes)
    {
        std::vector<CryptoPP::byte> cryptopp_bytes;
        cryptopp_bytes.reserve(bytes.size());
        std::ranges::transform(
            bytes, std::back_inserter(cryptopp_bytes),
            [](std::byte b) { return std::bit_cast<CryptoPP::byte>(b); });
        return cryptopp_bytes;
    }

    const CryptoPP::byte*
    bytes_to_cryptoppbytes_ptr(const std::vector<std::byte>& bytes)
    {
        return std::bit_cast<const CryptoPP::byte*>(bytes.data());
    }

    std::vector<std::byte> bytequeue_to_bytes(CryptoPP::ByteQueue& queue)
    {
        std::vector<CryptoPP::byte> cryptopp_bytes;

        CryptoPP::VectorSink sink{cryptopp_bytes};

        queue.TransferTo(sink);

        sink.MessageEnd();

        return cryptoppbytes_to_bytes(cryptopp_bytes);
    }

    [[nodiscard]] std::vector<std::byte> mpi_bytes(const CryptoPP::Integer& num)
    {
        using namespace CryptoPP;

        const size_t len = num.BitCount();

        std::vector<byte> bytes(2 + ((len + 8) >> 3));
        num.Encode(&bytes[2], bytes.size() - 2, Integer::UNSIGNED);

        bytes[0] = static_cast<byte>(len >> 8);
        bytes[1] = static_cast<byte>(len & 0xff);

        fmt::println("{:02x} Length: {}", fmt::join(bytes, " "), len);

        return cryptoppbytes_to_bytes(bytes);
    }

} // namespace

void Sha256::update(const std::vector<std::byte>& data)
{
    hasher_.Update(bytes_to_cryptoppbytes_ptr(data), data.size());
}

void Sha256::update(std::string_view str)
{
    hasher_.Update(std::bit_cast<CryptoPP::byte*>(str.data()), str.size());
}

std::array<std::byte, 32> Sha256::digest()
{
    std::array<std::byte, 32> digest{};
    hasher_.Final(std::bit_cast<CryptoPP::byte*>(digest.data()));
    return digest;
}

namespace dsa {
    namespace {
        struct GroupParameters {
            CryptoPP::Integer p;
            CryptoPP::Integer q;
            CryptoPP::Integer g;
        };

        const GroupParameters group_big_a_params{
            CryptoPP::Integer{
                "0x008608ac4f55361337f2a3e38ab1864ff3c98d66411d8d2afc9c526320c5"
                "41f65078e86bc78494a5d73e4a9a67583f941f2993ed6c97dbc795dd88f091"
                "5c9cfbffc7e5373cde13e3c7ca9073b9106eb31bf82272ed0057f984a870a1"
                "9f8a83bfa707d16440c382e62d3890473ea79e9d50c4ac6b1f1d30b10c32a0"
                "2f685833c6278fc29eb3439c5333885614a115219b3808c92a37a0f365cd5e"
                "61b5861761dad9eff0ce23250f558848f8db932b87a3bd8d7a2f7cf99c7582"
                "2bdc2fb7c1a1d78d0bcf81488ae0de5269ff853ab8b8f1f2bf3e6c0564573f"
                "612808f68dbfef49d5c9b4a705794cf7a424cd4eb1e0260552e67bfc1fa37b"
                "4a1f78b757ef185e86e9"},
            CryptoPP::Integer{"0x00b143368abcd51f58d6440d5417399339a4d15bef096a"
                              "2c5d8e6df44f52d6d379"},
            CryptoPP::Integer{
                "0x51a45ab670c1c9fd10bd395a6805d33339f5675e4b0d35defc9fa03aa5c2"
                "bf4ce9cfcdc256781291bfff6d546e67d47ae4e160f804ca72ec3c5492709f"
                "5f80f69e6346dd8d3e3d8433b6eeef63bce7f98574185c6aff161c9b536d76"
                "f873137365a4246cf414bfe8049ee11e31373cd0a6558e2950ef095320ce86"
                "218f992551cc292224114f3b60146d22dd51f8125c9da0c028126ffa85efd4"
                "f4bfea2c104453329cc1268a97e9a835c14e4a9a43c6a1886580e35ad8f1de"
                "230e1af32208ef9337f1924702a4514e95dc16f30f0c11e714a112ee84a9d8"
                "d6c9bc9e74e336560bb5cd4e91eabf6dad26bf0ca04807f8c31a2fc18ea7d4"
                "5baab7cc997b53c356"}};

        CryptoPP::DSA::PrivateKey
        load_priv_key(const std::vector<std::byte>& key_bytes)
        {
            using namespace CryptoPP;

            AutoSeededRandomPool prng;

            DSA::PrivateKey private_key;
            private_key.AccessGroupParameters().Initialize(
                group_big_a_params.p, group_big_a_params.q,
                group_big_a_params.g);

            auto bytes_ptr = bytes_to_cryptoppbytes_ptr(key_bytes);
            ByteQueue queue;
            queue.Put(bytes_ptr, key_bytes.size());
            queue.MessageEnd();

            private_key.BERDecodePrivateKey(queue, false,
                                            queue.MaxRetrievable());

            if (!private_key.Validate(prng, 3)) {
                throw std::runtime_error("Dsa private key validation failed");
            }

            return private_key;
        }

        CryptoPP::DSA::PublicKey
        load_pub_key(const std::vector<std::byte>& key_bytes)
        {
            using namespace CryptoPP;

            AutoSeededRandomPool prng;

            DSA::PublicKey pub_key;
            pub_key.AccessGroupParameters().Initialize(group_big_a_params.p,
                                                       group_big_a_params.q,
                                                       group_big_a_params.g);

            auto bytes_ptr = bytes_to_cryptoppbytes_ptr(key_bytes);
            ByteQueue queue;
            queue.Put(bytes_ptr, key_bytes.size());
            queue.MessageEnd();

            pub_key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());

            if (!pub_key.Validate(prng, 3)) {
                throw std::runtime_error("Dsa public key validation failed");
            }

            return pub_key;
        }

        [[nodiscard]] std::vector<std::byte>
        priv_key_to_bytes(const CryptoPP::DSA::PrivateKey& priv_key)
        {
            using namespace CryptoPP;
            ByteQueue priv_key_queue;
            priv_key.DEREncodePrivateKey(priv_key_queue);

            return bytequeue_to_bytes(priv_key_queue);
        }

        [[nodiscard]] std::vector<std::byte>
        pub_key_to_bytes(const CryptoPP::DSA::PublicKey& pub_key)
        {
            using namespace CryptoPP;
            ByteQueue pub_key_queue;
            pub_key.DEREncodePublicKey(pub_key_queue);

            return bytequeue_to_bytes(pub_key_queue);
        }

    } // namespace

    std::vector<std::byte>
    priv_key_bytes_to_pkcs8(const std::vector<std::byte>& key_bytes)
    {
        using namespace CryptoPP;

        const auto priv_key = load_priv_key(key_bytes);
        ByteQueue priv_key_queue;
        priv_key.Save(priv_key_queue);

        return bytequeue_to_bytes(priv_key_queue);
    }

    std::vector<std::byte>
    pub_key_bytes_to_x509(const std::vector<std::byte>& key_bytes)
    {
        using namespace CryptoPP;

        const auto pub_key = load_pub_key(key_bytes);
        ByteQueue pub_key_queue;
        pub_key.Save(pub_key_queue);

        return bytequeue_to_bytes(pub_key_queue);
    }

    std::pair<std::vector<std::byte>, std::vector<std::byte>> generate_keys()
    {
        using namespace CryptoPP;

        AutoSeededRandomPool prng;

        DSA::PrivateKey priv_key;
        DSA::PublicKey pub_key;

        while (!priv_key.Validate(prng, 3) || !pub_key.Validate(prng, 3)) {
            // Generate Private Key
            priv_key.Initialize(prng, group_big_a_params.p,
                                group_big_a_params.q, group_big_a_params.g);

            // Generate Public Key
            pub_key.AssignFrom(priv_key);
        }

        return {priv_key_to_bytes(priv_key), pub_key_to_bytes(pub_key)};
    }

    std::vector<std::byte>
    sign(const std::vector<std::byte>& priv_key_bytes, // NOLINT
         const std::vector<std::byte>& message_bytes) // NOLINT
    {
        using namespace CryptoPP;

        AutoSeededRandomPool prng;

        auto priv_key = load_priv_key(priv_key_bytes);
        auto message = bytes_to_cryptoppbytes_ptr(message_bytes);

        std::string signature;

        const DSA::Signer signer(priv_key);
        const ArraySource ss1(
            message, message_bytes.size(), true,
            new SignerFilter(prng, signer,
                             new StringSink(signature)) // SignerFilter
        ); // StringSource

        return support::util::str_to_bytes(signature);
    }

    bool verify(const std::vector<std::byte>& pub_key_bytes, // NOLINT
                const std::vector<std::byte>& message_bytes, // NOLINT
                const std::vector<std::byte>& signature) // NOLINT
    {
        using namespace CryptoPP;

        auto pub_key = load_pub_key(pub_key_bytes);

        bool result = false; // NOLINT

        const DSA::Verifier verifier(pub_key);
        std::vector<std::byte> data_to_verify;
        data_to_verify.insert(data_to_verify.end(), message_bytes.begin(),
                              message_bytes.end());
        data_to_verify.insert(data_to_verify.end(), signature.begin(),
                              signature.end());

        auto data_to_verify_ptr = bytes_to_cryptoppbytes_ptr(data_to_verify);

        const ArraySource ss(
            data_to_verify_ptr, data_to_verify.size(), true,
            new SignatureVerificationFilter(
                verifier,
                new ArraySink(std::bit_cast<byte*>(&result), sizeof(result)),
                SignatureVerificationFilter::PUT_RESULT
                    | SignatureVerificationFilter::SIGNATURE_AT_END));

        return result;
    }

    std::vector<std::byte>
    priv_key_bytes_to_mpi_bytes(const std::vector<std::byte>& priv_key_bytes)
    {
        using namespace CryptoPP;

        auto priv_key = load_priv_key(priv_key_bytes);

        return mpi_bytes(priv_key.GetPrivateExponent());
    }

    std::vector<std::byte>
    pub_key_bytes_to_mpi_bytes(const std::vector<std::byte>& pub_key_bytes)
    {
        using namespace CryptoPP;

        auto pub_key = load_pub_key(pub_key_bytes);

        return mpi_bytes(pub_key.GetPublicElement());
    }

} // namespace dsa

} // namespace crypto