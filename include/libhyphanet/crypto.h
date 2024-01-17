#ifndef LIBHYPHANET_CRYPTO_H
#define LIBHYPHANET_CRYPTO_H

#include <array>
#include <cryptopp/config_int.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/integer.h>
#include <cryptopp/queue.h>
#include <cstddef>
#include <vector>

namespace crypto {

/**
 * Encrypts the input using the Rijndael algorithm with a 256-bit key and
 * 256-bit block size.
 *
 * @param key the 256-bit key used for encryption.
 * @param input the input data to be encrypted.
 *
 * @return the encrypted data.
 */
[[nodiscard]] std::array<std::byte, 32>
rijndael256_256_encrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);

/**
 * Decrypts the input using the Rijndael algorithm with a 256-bit key and
 * 256-bit block size.
 *
 * @param key the 256-bit key used for decryption
 * @param input the input data to be decrypted
 *
 * @return the decrypted data.
 */
[[nodiscard]] std::array<std::byte, 32>
rijndael256_256_decrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);

namespace cryptopp {

    [[nodiscard]] std::vector<std::byte>
    cryptoppbytes_to_bytes(const std::vector<CryptoPP::byte>& cryptopp_bytes);

    [[nodiscard]] std::vector<CryptoPP::byte>
    bytes_to_cryptoppbytes(const std::vector<std::byte>& bytes);

    [[nodiscard]] std::vector<std::byte>
    bytequeue_to_bytes(CryptoPP::ByteQueue& queue);

    [[nodiscard]] std::vector<std::byte>
    pubkey_to_bytes(const CryptoPP::PublicKey& key);

} // namespace cryptopp

namespace dsa {
    [[nodiscard]] std::vector<std::byte>
    priv_key_bytes_to_pkcs8(const std::vector<std::byte>& key_bytes);

    [[nodiscard]] std::vector<std::byte>
    pub_key_bytes_to_x509(const std::vector<std::byte>& key_bytes);

    [[nodiscard]] std::pair<std::vector<std::byte>, std::vector<std::byte>>
    generate_keys();

    [[nodiscard]] std::vector<std::byte>
    sign(const std::vector<std::byte>& priv_key_bytes,
         const std::vector<std::byte>& message_bytes);

    [[nodiscard]] bool verify(const std::vector<std::byte>& pub_key_bytes,
                              const std::vector<std::byte>& message_bytes,
                              const std::vector<std::byte>& signature);

} // namespace dsa

} // namespace crypto

#endif /* LIBHYPHANET_CRYPTO_H */
