/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef CPPCRYPTO_RIJNDAEL_H
#define CPPCRYPTO_RIJNDAEL_H

#include "alignedarray.h"
#include "block_cipher.h"
#include "rijndael-impl.h"
#include <stdint.h>

namespace cppcrypto {
namespace detail {
    class rijndael256 : public block_cipher {
    public:
        rijndael256() = default;
        ~rijndael256() override;

        size_t blocksize() const override { return 256; }

        void encrypt_block(const unsigned char* in,
                           unsigned char* out) override;
        void decrypt_block(const unsigned char* in,
                           unsigned char* out) override;

        void encrypt_blocks(const unsigned char* in, unsigned char* out,
                            size_t n) override;
        void decrypt_blocks(const unsigned char* in, unsigned char* out,
                            size_t n) override;
    protected:
        aligned_pod_array<uint32_t, 120, 64> W_;
        detail::rijndael_impl* impl_{nullptr};
    };
} // namespace detail

class rijndael256_256 : public detail::rijndael256 {
public:
    rijndael256_256();
    ~rijndael256_256() override;

    size_t keysize() const override { return 256; }

    bool init(const unsigned char* key,
              block_cipher::direction direction) override;
};

} // namespace cppcrypto

#endif /* CPPCRYPTO_RIJNDAEL_H */
