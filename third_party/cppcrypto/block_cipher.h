/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef INCLUDE_BLOCK_CIPHER_H
#define INCLUDE_BLOCK_CIPHER_H

#ifndef CPPCRYPTO_BLOCK_CIPHER_H
#define CPPCRYPTO_BLOCK_CIPHER_H

#include <stdint.h>
#include <string>

namespace cppcrypto {

class block_cipher {
public:
    enum class direction { encryption, decryption };

    block_cipher() = default;
    virtual ~block_cipher() = default;

    virtual size_t blocksize() const = 0;
    virtual size_t keysize() const = 0;

    virtual bool init(const unsigned char* key,
                      block_cipher::direction direction)
        = 0;
    virtual void encrypt_block(const unsigned char* in, unsigned char* out) = 0;
    virtual void decrypt_block(const unsigned char* in, unsigned char* out) = 0;

    virtual void encrypt_blocks(const unsigned char* in, unsigned char* out,
                                size_t n);
    virtual void decrypt_blocks(const unsigned char* in, unsigned char* out,
                                size_t n);
private:
    block_cipher(const block_cipher&) = delete;
    void operator=(const block_cipher&) = delete;
};

class tweakable_block_cipher : public block_cipher {
public:
    virtual size_t tweaksize() const = 0;
    virtual void set_tweak(const unsigned char* tweak) = 0;
};

} // namespace cppcrypto

#endif

#endif /* INCLUDE_BLOCK_CIPHER_H */
