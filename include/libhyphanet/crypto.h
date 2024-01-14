#ifndef LIBHYPHANET_CRYPTO_H
#define LIBHYPHANET_CRYPTO_H

#include <array>
namespace crypto {

std::array<std::byte, 32>
rijndael256_256_encrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);
std::array<std::byte, 32>
rijndael256_256_decrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);

} // namespace crypto

#endif /* LIBHYPHANET_CRYPTO_H */
