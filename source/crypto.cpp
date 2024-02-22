#include "libhyphanet/crypto.h"
#include "cppcrypto/block_cipher.h"
#include "cppcrypto/rijndael.h"
#include "libhyphanet/support.h"
#include <algorithm>
#include <array>
#include <bit>
#include <cryptopp/config_int.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cstddef>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
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
    /**
     * @brief Converts a vector of CryptoPP bytes to a vector of std::byte.
     *
     * @details
     * This utility function transforms a vector of bytes from the CryptoPP
     * library's byte type to the standard C++ std::byte type.
     *
     * @param cryptopp_bytes The vector of CryptoPP bytes to convert.
     *
     * @return A vector of std::byte.
     */
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

    /**
     * @brief Converts a vector of std::byte to a vector of CryptoPP bytes.
     *
     * @details
     * This utility function transforms a vector of bytes from the standard C++
     * std::byte type to the CryptoPP library's byte type.
     *
     * @param bytes The vector of std::byte to convert.
     *
     * @return A vector of CryptoPP::byte.
     */
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

    /**
     * @brief Converts a vector of std::byte to a pointer to CryptoPP bytes.
     *
     * @details
     * This utility function provides a way to convert a vector of std::byte to
     * a pointer that can be used with CryptoPP functions expecting a byte
     * pointer.
     *
     * @param bytes The vector of std::byte to convert.
     *
     * @return A pointer to the converted CryptoPP::byte array.
     */
    const CryptoPP::byte*
    bytes_to_cryptoppbytes_ptr(const std::vector<std::byte>& bytes)
    {
        return std::bit_cast<const CryptoPP::byte*>(bytes.data());
    }

    /**
     * @brief Converts a CryptoPP ByteQueue to a vector of std::byte.
     *
     * @details
     * This function extracts bytes from a CryptoPP ByteQueue and converts them
     * to a vector of std::byte.
     *
     * @param queue The CryptoPP ByteQueue to convert.
     *
     * @return A vector of std::byte.
     */
    std::vector<std::byte> bytequeue_to_bytes(CryptoPP::ByteQueue& queue)
    {
        std::vector<CryptoPP::byte> cryptopp_bytes;

        CryptoPP::VectorSink sink{cryptopp_bytes};

        queue.TransferTo(sink);

        sink.MessageEnd();

        return cryptoppbytes_to_bytes(cryptopp_bytes);
    }

    /**
     * @brief Converts a CryptoPP Integer to a vector of std::byte in MPI
     * format.
     *
     * @details
     * This function encodes a CryptoPP Integer to a vector of std::byte,
     * representing the integer in MPI (Multiple Precision Integer) format.
     *
     * @param num The CryptoPP Integer to convert.
     *
     * @return A vector of std::byte representing the integer in MPI format.
     */
    [[nodiscard]] std::vector<std::byte> mpi_bytes(const CryptoPP::Integer& num)
    {
        using namespace CryptoPP;

        const size_t len = num.BitCount();

        std::vector<byte> bytes(2 + ((len + 8) >> 3));
        num.Encode(&bytes[2], bytes.size() - 2, Integer::UNSIGNED);

        bytes[0] = static_cast<byte>(len >> 8);
        bytes[1] = static_cast<byte>(len & 0xff);

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
        /**
         * @brief Holds the DSA group parameters (p, q, g).
         *
         * @details
         * This structure encapsulates the DSA group parameters, which are three
         * large prime numbers that define the finite field and subgroup used
         * for DSA operations.
         */
        struct Group_parameters {
            CryptoPP::Integer p; ///< The prime modulus p.
            CryptoPP::Integer q; ///< The prime divisor q.
            CryptoPP::Integer g; ///< The base generator g.
        };

        /**
         * @brief Predefined DSA group parameters for a specific DSA group.
         *
         * @details
         * This variable holds a set of predefined DSA group parameters for a
         * specific DSA group. These parameters are used to initialize DSA key
         * objects for cryptographic operations.
         */
        const Group_parameters group_big_a_params{
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

        /**
         * @brief Loads a DSA private key from a byte vector.
         *
         * @details
         * This function takes a byte vector representing a DSA private key and
         * initializes a
         * [CryptoPP::DSA::PrivateKey](https://cryptopp.com/docs/ref/class_d_l___private_key___g_f_p.html)
         * object with it. It throws an exception if the key is invalid or
         * cannot be loaded.
         *
         * @param key_bytes The byte vector containing the DSA private key.
         *
         * @return A
         * [CryptoPP::DSA::PrivateKey](https://cryptopp.com/docs/ref/class_d_l___private_key___g_f_p.html)
         * object.
         *
         * @throws Invalid_priv_key_error if the key is invalid or cannot be
         * loaded.
         */
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

            try {
                // Big endian encoded big integer private key
                const Integer x{bytes_ptr, key_bytes.size()};
                private_key.SetPrivateExponent(x);
            }
            catch (CryptoPP::Exception&) {
                throw Invalid_priv_key_error("Unable to load dsa private key");
            }

            if (!private_key.Validate(prng, 3)) {
                throw Invalid_pub_key_error(
                    "Dsa private key validation failed");
            }

            return private_key;
        }

        /**
         * @brief Loads a DSA public key from a byte vector.
         *
         * @details
         * This function takes a byte vector representing a DSA public key and
         * initializes a
         * [CryptoPP::DSA::PublicKey](https://cryptopp.com/docs/ref/class_d_l___public_key___g_f_p.html)
         * object with it. It throws an exception if the key is invalid or
         * cannot be loaded.
         *
         * @param key_bytes The byte vector containing the DSA public key.
         *
         * @return A
         * [CryptoPP::DSA::PublicKey](https://cryptopp.com/docs/ref/class_d_l___public_key___g_f_p.html)
         * object.
         *
         * @throws Invalid_pub_key_error if the key is invalid or cannot be
         * loaded.
         */
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

            try {
                const Integer y{bytes_ptr, key_bytes.size()};
                pub_key.SetPublicElement(y);
            }
            catch (CryptoPP::Exception&) {
                throw Invalid_pub_key_error("Unable to load dsa public key");
            }

            if (!pub_key.Validate(prng, 3)) {
                throw Invalid_pub_key_error("Dsa public key validation failed");
            }

            return pub_key;
        }

        /**
         * @brief Converts a DSA private key to a byte vector.
         *
         * @details
         * This function takes a
         * [CryptoPP::DSA::PrivateKey](https://cryptopp.com/docs/ref/class_d_l___private_key___g_f_p.html)
         * object and converts it to a byte vector. The private key bytes are
         * big-endian encoded `x` values.
         *
         * @param priv_key The DSA private key to convert.
         *
         * @return A byte vector representing the DSA private key.
         */
        [[nodiscard]] std::vector<std::byte>
        priv_key_to_bytes(const CryptoPP::DSA::PrivateKey& priv_key)
        {
            using namespace CryptoPP;

            const auto& x = priv_key.GetPrivateExponent();

            const size_t encoded_size = x.MinEncodedSize();
            std::vector<byte> encoded(encoded_size);

            x.Encode(encoded.data(), encoded_size);

            return cryptoppbytes_to_bytes(encoded);
        }

        /**
         * @brief Converts a DSA public key to a byte vector.
         *
         * @details
         * This function takes a
         * [CryptoPP::DSA::PublicKey](https://cryptopp.com/docs/ref/class_d_l___public_key___g_f_p.html)
         * object and converts it to a byte vector. The public key bytes are
         * big-endian encoded `y` values.
         *
         * @param pub_key The DSA public key to convert.
         * @return A byte vector representing the DSA public key.
         */
        [[nodiscard]] std::vector<std::byte>
        pub_key_to_bytes(const CryptoPP::DSA::PublicKey& pub_key)
        {
            using namespace CryptoPP;

            const auto& y = pub_key.GetPublicElement();

            const size_t encoded_size = y.MinEncodedSize();
            std::vector<byte> encoded(encoded_size);

            y.Encode(encoded.data(), encoded_size);

            return cryptoppbytes_to_bytes(encoded);
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
        CryptoPP::AutoSeededRandomPool prng;
        return generate_keys(prng);
    }

    std::pair<std::vector<std::byte>, std::vector<std::byte>>
    generate_keys(CryptoPP::RandomNumberGenerator& rng)
    {
        using namespace CryptoPP;

        DSA::PrivateKey priv_key;
        DSA::PublicKey pub_key;

        while (!priv_key.Validate(rng, 3) || !pub_key.Validate(rng, 3)) {
            // Generate Private Key
            priv_key.Initialize(rng, group_big_a_params.p, group_big_a_params.q,
                                group_big_a_params.g);

            // Generate Public Key
            pub_key.AssignFrom(priv_key);
        }

        return {priv_key_to_bytes(priv_key), pub_key_to_bytes(pub_key)};
    }

    std::vector<std::byte>
    make_pub_key(const std::vector<std::byte>& priv_key_bytes)
    {
        using namespace CryptoPP;

        auto priv_key = load_priv_key(priv_key_bytes);

        DSA::PublicKey pub_key;
        priv_key.MakePublicKey(pub_key);

        return pub_key_to_bytes(pub_key);
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

    std::vector<std::byte> group_to_mpi_bytes()
    {
        auto pb = mpi_bytes(group_big_a_params.p);
        auto qb = mpi_bytes(group_big_a_params.q);
        auto gb = mpi_bytes(group_big_a_params.g);

        pb.insert(pb.end(), qb.begin(), qb.end());
        pb.insert(pb.end(), gb.begin(), gb.end());

        return pb;
    }

    std::vector<std::byte>
    pub_key_bytes_to_mpi_bytes(const std::vector<std::byte>& pub_key_bytes)
    {
        auto pub_key = load_pub_key(pub_key_bytes);

        auto group_bytes = group_to_mpi_bytes();
        auto y_bytes = mpi_bytes(pub_key.GetPublicElement());

        group_bytes.insert(group_bytes.end(), y_bytes.begin(), y_bytes.end());

        return group_bytes;
    }

    std::array<std::byte, 32>
    pub_key_hash(const std::vector<std::byte>& pub_key_bytes)
    {
        auto pub_key_mpi_bytes = pub_key_bytes_to_mpi_bytes(pub_key_bytes);

        auto sha256 = Sha256();
        sha256.update(pub_key_mpi_bytes);
        return sha256.digest();
    }

} // namespace dsa

} // namespace crypto