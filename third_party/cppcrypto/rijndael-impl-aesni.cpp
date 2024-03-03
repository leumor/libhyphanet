/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#include "block_cipher.h"
#include "portability.h"
#include "rijndael-impl-aesni-common.h"
#include "rijndael-impl.h"
#include <cstring>
#include <smmintrin.h>
#include <wmmintrin.h>

namespace cppcrypto {
namespace detail {
    bool rijndael256_256_impl_aesni::init(const unsigned char* key,
                                          block_cipher::direction direction)
    {
        __m128i temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
        __m128i temp3
            = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));
        __m128i temp2;
        rk[0] = temp1;
        rk[1] = temp3;

        KEYGEN256STEP(2, 0x01);
        KEYGEN256STEP(4, 0x02);
        KEYGEN256STEP(6, 0x04);
        KEYGEN256STEP(8, 0x08);
        KEYGEN256STEP(10, 0x10);
        KEYGEN256STEP(12, 0x20);
        KEYGEN256STEP(14, 0x40);
        KEYGEN256STEP(16, 0x80);
        KEYGEN256STEP(18, 0x1b);
        KEYGEN256STEP(20, 0x36);
        KEYGEN256STEP(22, 0x6c);
        KEYGEN256STEP(24, 0xd8);
        KEYGEN256STEP(26, 0xab);
        KEYGEN256STEP(28, 0x4d);

        if (direction == block_cipher::direction::decryption) {
            std::swap(rk[0], rk[28]);
            std::swap(rk[1], rk[29]);
            std::swap(rk[2], rk[26]);
            std::swap(rk[3], rk[27]);
            std::swap(rk[4], rk[24]);
            std::swap(rk[5], rk[25]);
            std::swap(rk[6], rk[22]);
            std::swap(rk[7], rk[23]);
            std::swap(rk[8], rk[20]);
            std::swap(rk[9], rk[21]);
            std::swap(rk[10], rk[18]);
            std::swap(rk[11], rk[19]);
            std::swap(rk[12], rk[16]);
            std::swap(rk[13], rk[17]);

            for (int i = 2; i < 28; i++) rk[i] = _mm_aesimc_si128(rk[i]);
        }

        return true;
    }

    void rijndael256_256_impl_aesni::encrypt_blocks(const unsigned char* in,
                                                    unsigned char* out,
                                                    size_t n)
    {
        __m128i RIJNDAEL256_MASK = _mm_set_epi32(
            static_cast<int>(0x03020d0c), static_cast<int>(0x0f0e0908),
            static_cast<int>(0x0b0a0504), static_cast<int>(0x07060100));
        __m128i BLEND_MASK = _mm_set_epi32(
            static_cast<int>(0x80000000), static_cast<int>(0x80800000),
            static_cast<int>(0x80800000), static_cast<int>(0x80808000));

        size_t x8 = n / 4;
        int j;

        for (size_t i = 0; i < x8; i++) {
            __m128i data1_0
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[0]);
            __m128i data2_0
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[1]);
            __m128i data1_1
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[2]);
            __m128i data2_1
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[3]);
            __m128i data1_2
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[4]);
            __m128i data2_2
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[5]);
            __m128i data1_3
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[6]);
            __m128i data2_3
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[7]);

            data1_0 = _mm_xor_si128(data1_0, rk[0]);
            data1_1 = _mm_xor_si128(data1_1, rk[0]);
            data1_2 = _mm_xor_si128(data1_2, rk[0]);
            data1_3 = _mm_xor_si128(data1_3, rk[0]);
            data2_0 = _mm_xor_si128(data2_0, rk[1]);
            data2_1 = _mm_xor_si128(data2_1, rk[1]);
            data2_2 = _mm_xor_si128(data2_2, rk[1]);
            data2_3 = _mm_xor_si128(data2_3, rk[1]);

            for (j = 1; j < 14; j++) {
                __m128i tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_0, data2_0, BLEND_MASK),
                    RIJNDAEL256_MASK);
                __m128i tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_0, data1_0, BLEND_MASK),
                    RIJNDAEL256_MASK);
                data1_0 = _mm_aesenc_si128(tmp1, rk[j * 2]);
                data2_0 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_1, data2_1, BLEND_MASK),
                    RIJNDAEL256_MASK);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_1, data1_1, BLEND_MASK),
                    RIJNDAEL256_MASK);
                data1_1 = _mm_aesenc_si128(tmp1, rk[j * 2]);
                data2_1 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_2, data2_2, BLEND_MASK),
                    RIJNDAEL256_MASK);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_2, data1_2, BLEND_MASK),
                    RIJNDAEL256_MASK);
                data1_2 = _mm_aesenc_si128(tmp1, rk[j * 2]);
                data2_2 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_3, data2_3, BLEND_MASK),
                    RIJNDAEL256_MASK);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_3, data1_3, BLEND_MASK),
                    RIJNDAEL256_MASK);
                data1_3 = _mm_aesenc_si128(tmp1, rk[j * 2]);
                data2_3 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
            }

            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[0],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_0, data2_0, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[1],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_0, data1_0, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[2],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_1, data2_1, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[3],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_1, data1_1, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[4],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_2, data2_2, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[5],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_2, data1_2, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[6],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_3, data2_3, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[7],
                _mm_aesenclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_3, data1_3, BLEND_MASK),
                        RIJNDAEL256_MASK),
                    rk[j * 2 + 1]));

            in += 32 * 4;
            out += 32 * 4;
        }
        n -= x8 * 4;

        for (size_t i = 0; i < n; i++) {
            encrypt_block(in, out);
            in += 32;
            out += 32;
        }
    }

    void rijndael256_256_impl_aesni::encrypt_block(const unsigned char* in,
                                                   unsigned char* out)
    {
        __m128i tmp1, tmp2, data1, data2;
        __m128i RIJNDAEL256_MASK = _mm_set_epi32(
            static_cast<int>(0x03020d0c), static_cast<int>(0x0f0e0908),
            static_cast<int>(0x0b0a0504), static_cast<int>(0x07060100));
        __m128i BLEND_MASK = _mm_set_epi32(
            static_cast<int>(0x80000000), static_cast<int>(0x80800000),
            static_cast<int>(0x80800000), static_cast<int>(0x80808000));
        int j;

        data1 = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[0]);
        data2 = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[1]);
        data1 = _mm_xor_si128(data1, rk[0]);
        data2 = _mm_xor_si128(data2, rk[1]);
        for (j = 1; j < 14; j++) {
            tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
            tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
            tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
            tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
            data1 = _mm_aesenc_si128(tmp1, rk[j * 2]);
            data2 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
        }

        tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
        tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
        tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
        tmp1 = _mm_aesenclast_si128(tmp1, rk[j * 2 + 0]);
        tmp2 = _mm_aesenclast_si128(tmp2, rk[j * 2 + 1]);
        _mm_storeu_si128(&(reinterpret_cast<__m128i*>(out))[0], tmp1);
        _mm_storeu_si128(&(reinterpret_cast<__m128i*>(out))[1], tmp2);
    }

    void rijndael256_256_impl_aesni::decrypt_blocks(const unsigned char* in,
                                                    unsigned char* out,
                                                    size_t n)
    {
        __m128i RIJNDAEL256_MASK_INV = _mm_set_epi32(
            static_cast<int>(0x0b0a0d0c), static_cast<int>(0x07060908),
            static_cast<int>(0x03020504), static_cast<int>(0x0f0e0100));
        __m128i BLEND_MASK_INV = _mm_set_epi32(
            static_cast<int>(0x80808000), static_cast<int>(0x80800000),
            static_cast<int>(0x80800000), static_cast<int>(0x80000000));

        size_t x8 = n / 4;
        int j;

        for (size_t i = 0; i < x8; i++) {
            __m128i data1_0
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[0]);
            __m128i data2_0
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[1]);
            __m128i data1_1
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[2]);
            __m128i data2_1
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[3]);
            __m128i data1_2
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[4]);
            __m128i data2_2
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[5]);
            __m128i data1_3
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[6]);
            __m128i data2_3
                = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[7]);

            data1_0 = _mm_xor_si128(data1_0, rk[0]);
            data1_1 = _mm_xor_si128(data1_1, rk[0]);
            data1_2 = _mm_xor_si128(data1_2, rk[0]);
            data1_3 = _mm_xor_si128(data1_3, rk[0]);
            data2_0 = _mm_xor_si128(data2_0, rk[1]);
            data2_1 = _mm_xor_si128(data2_1, rk[1]);
            data2_2 = _mm_xor_si128(data2_2, rk[1]);
            data2_3 = _mm_xor_si128(data2_3, rk[1]);

            for (j = 1; j < 14; j++) {
                __m128i tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_0, data2_0, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                __m128i tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_0, data1_0, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                data1_0 = _mm_aesdec_si128(tmp1, rk[j * 2]);
                data2_0 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_1, data2_1, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_1, data1_1, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                data1_1 = _mm_aesdec_si128(tmp1, rk[j * 2]);
                data2_1 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_2, data2_2, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_2, data1_2, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                data1_2 = _mm_aesdec_si128(tmp1, rk[j * 2]);
                data2_2 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
                tmp1 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data1_3, data2_3, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                tmp2 = _mm_shuffle_epi8(
                    _mm_blendv_epi8(data2_3, data1_3, BLEND_MASK_INV),
                    RIJNDAEL256_MASK_INV);
                data1_3 = _mm_aesdec_si128(tmp1, rk[j * 2]);
                data2_3 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
            }

            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[0],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_0, data2_0, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[1],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_0, data1_0, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[2],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_1, data2_1, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[3],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_1, data1_1, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[4],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_2, data2_2, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[5],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_2, data1_2, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 1]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[6],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data1_3, data2_3, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 0]));
            _mm_storeu_si128(
                &(reinterpret_cast<__m128i*>(out))[7],
                _mm_aesdeclast_si128(
                    _mm_shuffle_epi8(
                        _mm_blendv_epi8(data2_3, data1_3, BLEND_MASK_INV),
                        RIJNDAEL256_MASK_INV),
                    rk[j * 2 + 1]));

            in += 32 * 4;
            out += 32 * 4;
        }
        n -= x8 * 4;

        for (size_t i = 0; i < n; i++) {
            encrypt_block(in, out);
            in += 32;
            out += 32;
        }
    }

    void rijndael256_256_impl_aesni::decrypt_block(const unsigned char* in,
                                                   unsigned char* out)
    {
        __m128i tmp1, tmp2, data1, data2;
        __m128i RIJNDAEL256_MASK_INV = _mm_set_epi32(
            static_cast<int>(0x0b0a0d0c), static_cast<int>(0x07060908),
            static_cast<int>(0x03020504), static_cast<int>(0x0f0e0100));
        __m128i BLEND_MASK_INV = _mm_set_epi32(
            static_cast<int>(0x80808000), static_cast<int>(0x80800000),
            static_cast<int>(0x80800000), static_cast<int>(0x80000000));
        int j;

        data1 = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[0]);
        data2 = _mm_loadu_si128(&(reinterpret_cast<const __m128i*>(in))[1]);
        data1 = _mm_xor_si128(data1, rk[0]);
        data2 = _mm_xor_si128(data2, rk[1]);
        for (j = 1; j < 14; j++) {
            tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK_INV);
            tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK_INV);
            tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK_INV);
            tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK_INV);
            data1 = _mm_aesdec_si128(tmp1, rk[j * 2]);
            data2 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
        }

        tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK_INV);
        tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK_INV);
        tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK_INV);
        tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK_INV);
        tmp1 = _mm_aesdeclast_si128(tmp1, rk[j * 2 + 0]);
        tmp2 = _mm_aesdeclast_si128(tmp2, rk[j * 2 + 1]);
        _mm_storeu_si128(&(reinterpret_cast<__m128i*>(out))[0], tmp1);
        _mm_storeu_si128(&(reinterpret_cast<__m128i*>(out))[1], tmp2);
    }

} // namespace detail
} // namespace cppcrypto
