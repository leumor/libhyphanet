/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef INCLUDE_RIJNDAEL_IMPL_H
#define INCLUDE_RIJNDAEL_IMPL_H

#include "block_cipher.h"
#include <stdint.h>

#if defined(__i386__) || defined(__x86_64__)
#include <emmintrin.h>
#endif

namespace cppcrypto {
namespace detail {
    class rijndael_impl {
    public:
        virtual ~rijndael_impl() {}
        virtual bool init(const unsigned char* key,
                          block_cipher::direction direction)
            = 0;
        virtual void encrypt_block(const unsigned char* in, unsigned char* out)
            = 0;
        virtual void decrypt_block(const unsigned char* in, unsigned char* out)
            = 0;

        virtual void encrypt_blocks(const unsigned char* in, unsigned char* out,
                                    size_t n)
            = 0;
        virtual void decrypt_blocks(const unsigned char* in, unsigned char* out,
                                    size_t n)
            = 0;
    };

#if defined(__i386__) || defined(__x86_64__)
    class rijndael256_256_impl_aesni : public rijndael_impl {
    protected:
        __m128i rk[30];
    public:
        bool init(const unsigned char* key,
                  block_cipher::direction direction) override;
        void encrypt_block(const unsigned char* in,
                           unsigned char* out) override;
        void decrypt_block(const unsigned char* in,
                           unsigned char* out) override;
        void encrypt_blocks(const unsigned char* in, unsigned char* out,
                            size_t n) override;
        void decrypt_blocks(const unsigned char* in, unsigned char* out,
                            size_t n) override;
    };
#endif
} // namespace detail
} // namespace cppcrypto

#endif /* INCLUDE_RIJNDAEL_IMPL_H */
