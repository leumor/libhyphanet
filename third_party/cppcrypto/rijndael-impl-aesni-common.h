/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef CPPCRYPTO_RIJNDAEL_IMPL_AESNI_COMMON_H
#define CPPCRYPTO_RIJNDAEL_IMPL_AESNI_COMMON_H

#include <smmintrin.h>
#include <wmmintrin.h>

namespace cppcrypto {
namespace detail {

    static inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i* temp2)
    {
        __m128i temp4;
        *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
        temp4 = _mm_slli_si128(*temp1, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        *temp1 = _mm_xor_si128(*temp1, *temp2);
    }
    static inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i* temp3)
    {
        __m128i temp2, temp4;
        temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
        temp2 = _mm_shuffle_epi32(temp4, 0xaa);
        temp4 = _mm_slli_si128(*temp3, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        *temp3 = _mm_xor_si128(*temp3, temp2);
    }

#define KEYGEN256STEP(idx, rc)                                                 \
    temp2 = _mm_aeskeygenassist_si128(temp3, rc);                              \
    KEY_256_ASSIST_1(&temp1, &temp2);                                          \
    rk[idx] = temp1;                                                           \
    KEY_256_ASSIST_2(&temp1, &temp3);                                          \
    rk[idx + 1] = temp3;

    inline static __m128i mm_blend_int64(__m128i t1, __m128i t2, const int mask)
    {
        __m128d f1 = _mm_castsi128_pd(t1);
        __m128d f2 = _mm_castsi128_pd(t2);
        f1 = _mm_blend_pd(f1, f2, 1);
        return _mm_castpd_si128(f1);
    }

    inline static __m128i mm_blend_shuffle_int64(__m128i t1, __m128i t2,
                                                 const int mask)
    {
        __m128d f1 = _mm_castsi128_pd(t1);
        __m128d f2 = _mm_castsi128_pd(t2);
        f1 = _mm_blend_pd(f1, f2, 1);
        f1 = _mm_shuffle_pd(f1, f1, 1);
        return _mm_castpd_si128(f1);
    }

} // namespace detail
} // namespace cppcrypto

#endif /* CPPCRYPTO_RIJNDAEL_IMPL_AESNI_COMMON_H */
