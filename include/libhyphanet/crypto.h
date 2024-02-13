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

/**
 * @brief The crypto namespace contains functions and classes for cryptographic
 * operations.
 *
 * @details
 * This namespace includes functionality for encryption, decryption, and hashing
 * using various algorithms. It provides a high-level interface for secure
 * cryptographic transformations on data.
 */
namespace crypto {

/**
 * @brief Encrypts data using the Rijndael algorithm with a 256-bit key and
 * block size.
 *
 * @details
 * This function encrypts the input data using the Rijndael algorithm with a
 * specified 256-bit key. The encryption process is designed to work with a
 * 256-bit block size, ensuring a high level of security.
 *
 * @param key the 256-bit key used for encryption.
 * @param input the input data to be encrypted.
 *
 * @return The encrypted data as a 32-byte array.
 */
[[nodiscard]] std::array<std::byte, 32>
rijndael256_256_encrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);

/**
 * @brief Decrypts data using the Rijndael algorithm with a 256-bit key and
 * block size.
 *
 * @details
 * This function decrypts the input data using the Rijndael algorithm with a
 * specified 256-bit key. The decryption process is designed to work with a
 * 256-bit block size, matching the encryption process for compatibility.
 *
 * @param key the 256-bit key used for decryption
 * @param input the input data to be decrypted
 *
 * @return The decrypted data as a 32-byte array.
 */
[[nodiscard]] std::array<std::byte, 32>
rijndael256_256_decrypt(const std::array<std::byte, 32>& key,
                        const std::array<std::byte, 32>& input);

/**
 * @brief Class for computing SHA-256 hashes.
 *
 * @details
 * This class provides functionality to compute SHA-256 hashes of input data. It
 * supports updating the hash with multiple inputs before finalizing the digest.
 */
class Sha256 {
public:
    Sha256() = default;
    Sha256(const Sha256& other) = delete;
    Sha256(Sha256&& other) noexcept = delete;
    Sha256& operator=(const Sha256& other) = delete;
    Sha256& operator=(Sha256&& other) noexcept = delete;
    ~Sha256() = default;

    /**
     * @brief Updates the hash with a vector of data.
     *
     * @param data The data to update the hash with.
     */
    void update(const std::vector<std::byte>& data);

    /**
     * @brief Updates the hash with a string view.
     *
     * @param str The string view to update the hash with.
     */
    void update(std::string_view str);

    /**
     * @brief Finalizes the hash and returns the digest.
     *
     * @return The SHA-256 digest as a 32-byte array.
     */
    [[nodiscard]] std::array<std::byte, 32> digest();
private:
    CryptoPP::SHA256 hasher_;
};

/**
 * @brief The dsa namespace within crypto contains functions and classes related
 * to the DSA (Digital Signature Algorithm).
 *
 * @details
 * This namespace provides tools for generating DSA keys, signing messages, and
 * verifying signatures. It also includes exceptions for handling errors related
 * to DSA operations.
 */
namespace dsa {
    /**
     * @brief Exception for invalid private key errors.
     */
    class Invalid_priv_key_error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    /**
     * @brief Exception for invalid public key errors.
     */
    class Invalid_pub_key_error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    /**
     * @brief Converts private key bytes to PKCS#8 format.
     *
     * @details
     * This function takes a vector of bytes representing a private key and
     * converts it into PKCS#8 format.
     *
     * @param key_bytes The private key bytes.
     *
     * @return The private key in PKCS#8 format as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte>
    priv_key_bytes_to_pkcs8(const std::vector<std::byte>& key_bytes);

    /**
     * @brief Converts public key bytes to X.509 format.
     *
     * @details
     * This function takes a vector of bytes representing a public key and
     * converts it into X.509 format.
     *
     * @param key_bytes The public key bytes.
     *
     * @return The public key in X.509 format as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte>
    pub_key_bytes_to_x509(const std::vector<std::byte>& key_bytes);

    /**
     * @brief Generates a pair of DSA private and public keys.
     *
     * @details
     * This function generates a new pair of DSA private and public keys using
     * default cryptographic random number generation
     * ([CryptoPP::AutoSeededRandomPool](https://cryptopp.com/docs/ref/class_auto_seeded_random_pool.html)).
     *
     * @return A pair of vectors, where the first vector is the private key
     * bytes and the second is the public key bytes. The private key bytes are
     * big-endian encoded `x` values, and the public key bytes are big-endian
     * encoded `y` values.
     */
    [[nodiscard]] std::pair<std::vector<std::byte>, std::vector<std::byte>>
    generate_keys();

    /**
     * @brief Generates a pair of DSA private and public keys using a specified
     * random number generator.
     *
     * @details
     * This function generates a new pair of DSA private and public keys using a
     * specified random number generator for cryptographic operations.
     *
     * @param rng The random number generator to use.
     *
     * @return A pair of vectors, where the first vector is the private key
     * bytes and the second is the public key bytes.
     */
    [[nodiscard]] std::pair<std::vector<std::byte>, std::vector<std::byte>>
    generate_keys(CryptoPP::RandomNumberGenerator& rng);

    /**
     * @brief Creates a public key from a given private key bytes.
     *
     * @details
     * This function computes the corresponding public key from the given
     * private key bytes. The private key bytes are big-endian encoded `x`
     * values.
     *
     * @param priv_key_bytes The private key bytes.
     *
     * @return The public key bytes.
     */
    [[nodiscard]] std::vector<std::byte>
    make_pub_key(const std::vector<std::byte>& priv_key_bytes);

    /**
     * @brief Signs a message using a DSA private key.
     *
     * @details
     * This function signs a given message using a DSA private key and returns
     * the signature.
     *
     * @param priv_key_bytes The private key bytes. The private key bytes are
     * big-endian encoded `x` values.
     * @param message_bytes The message to sign.
     *
     * @return The signature as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte>
    sign(const std::vector<std::byte>& priv_key_bytes,
         const std::vector<std::byte>& message_bytes);

    /**
     * @brief Verifies a signature using a DSA public key.
     *
     * @details
     * This function verifies a given signature against a message using a DSA
     * public key.
     *
     * @param pub_key_bytes The public key bytes. The public key bytes are
     * big-endian encoded `y` values.
     * @param message_bytes The message that was signed.
     * @param signature The signature to verify.
     *
     * @return `true` if the signature is valid, `false` otherwise.
     */
    [[nodiscard]] bool verify(const std::vector<std::byte>& pub_key_bytes,
                              const std::vector<std::byte>& message_bytes,
                              const std::vector<std::byte>& signature);

    /**
     * @brief Converts private key bytes to MPI (Multiple Precision Integer)
     * format.
     *
     * @details
     * This function converts private key bytes into MPI format, which is useful
     * for cryptographic operations requiring large integer representations.
     *
     * @param priv_key_bytes The private key bytes.
     *
     * @return The private key in MPI format as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte>
    priv_key_bytes_to_mpi_bytes(const std::vector<std::byte>& priv_key_bytes);

    /**
     * @brief Converts DSA group parameters to MPI (Multiple Precision Integer)
     * format.
     *
     * @details
     * This function converts DSA group parameters (p, q, g) into MPI format.
     *
     * @return The DSA group parameters in MPI format as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte> group_to_mpi_bytes();

    /**
     * @brief Converts public key bytes to MPI (Multiple Precision Integer)
     * format.
     *
     * @details
     * This function converts public key bytes into MPI format, which is useful
     * for cryptographic operations requiring large integer representations.
     *
     * @param pub_key_bytes The public key bytes.
     *
     * @return The public key in MPI format as a byte vector.
     */
    [[nodiscard]] std::vector<std::byte>
    pub_key_bytes_to_mpi_bytes(const std::vector<std::byte>& pub_key_bytes);

    /**
     * @brief Computes the SHA-256 hash of a DSA public key.
     *
     * @details
     * This function computes the SHA-256 hash of a DSA public key bytes,
     * providing a fixed-size representation of the key.
     *
     * @param pub_key_bytes The public key bytes.
     *
     * @return The SHA-256 hash of the public key as a 32-byte array.
     */
    [[nodiscard]] std::array<std::byte, 32>
    pub_key_hash(const std::vector<std::byte>& pub_key_bytes);

} // namespace dsa

} // namespace crypto

#endif /* LIBHYPHANET_CRYPTO_H */
