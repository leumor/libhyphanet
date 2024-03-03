/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef CPPCRYPTO_RIJNDAEL_IMPL_H
#define CPPCRYPTO_RIJNDAEL_IMPL_H

#include "block_cipher.h"
#include <stdint.h>

#if defined(__i386__) || defined(__x86_64__)
#include <emmintrin.h>
#endif

namespace cppcrypto::detail {
class rijndael_impl {
public:
    virtual ~rijndael_impl() = default;
    virtual bool init(const unsigned char* key,
                      block_cipher::direction direction)
        = 0;
    virtual void encrypt_block(const unsigned char* in, unsigned char* out) = 0;
    virtual void decrypt_block(const unsigned char* in, unsigned char* out) = 0;

    virtual void encrypt_blocks(const unsigned char* in, unsigned char* out,
                                size_t n)
        = 0;
    virtual void decrypt_blocks(const unsigned char* in, unsigned char* out,
                                size_t n)
        = 0;
};

#if defined(__i386__) || defined(__x86_64__)
class rijndael256_256_impl_aesni : public rijndael_impl {
public:
    bool init(const unsigned char* key,
              block_cipher::direction direction) override;
    void encrypt_block(const unsigned char* in, unsigned char* out) override;
    void decrypt_block(const unsigned char* in, unsigned char* out) override;
    void encrypt_blocks(const unsigned char* in, unsigned char* out,
                        size_t n) override;
    void decrypt_blocks(const unsigned char* in, unsigned char* out,
                        size_t n) override;
private:
    __m128i rk[30];
};
#endif
} // namespace cppcrypto::detail

#endif /* CPPCRYPTO_RIJNDAEL_IMPL_H */
