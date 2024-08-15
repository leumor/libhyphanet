#ifndef LIBHYPHANET_BLOCK_NODE_H
#define LIBHYPHANET_BLOCK_NODE_H

#include "libhyphanet/key/node.h"

#include <cstddef>
#include <libhyphanet/libhyphanet_export.h>
#include <vector>

namespace block::node {

namespace concepts {
    template<typename T>
    concept Has_Get_Node_Routing_Key = requires(const T t) {
        { t.get_node_routing_key() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Has_Get_Full_Key = requires(const T t) {
        { t.get_full_key() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Storable = Has_Get_Node_Routing_Key<T> && Has_Get_Full_Key<T>;

    template<typename T>
    concept Has_Get_Pub_Key = requires(const T t) {
        { t.get_pub_key() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Has_Get_Node_Key = requires(const T t) {
        { t.get_node_key() } -> std::same_as<std::shared_ptr<key::node::Key>>;
    };

    /**
     * Retrieves the raw headers of the Key.
     *
     * @return the raw headers as a vector of bytes.
     */
    template<typename T>
    concept Has_Get_Raw_Headers = requires(const T t) {
        { t.get_raw_headers() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * Retrieves the actual raw data of the Key.
     *
     * @return the raw data as a vector of bytes.
     */
    template<typename T>
    concept Has_Get_Raw_Data = requires(const T t) {
        { t.get_raw_data() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Has_Get_Hash_Identifier = requires(const T t) {
        { t.get_hash_identifier() } -> std::same_as<short>;
    };

    template<typename T>
    concept Has_Hash_Sha_256 = requires(const T t) {
        { T::hash_sha_256 } -> std::same_as<const short&>;
    };

    /**
     * @brief Abstract class for fetched blocks.
     *
     * @details
     * Can be decoded by using a key::user::Key to
     * construct a block::user::Key, which can then be decoded to a
     * block::Bucket.
     */
    template<typename T>
    concept Key = Storable<T> && Has_Get_Pub_Key<T> && Has_Get_Node_Key<T>
               && Has_Get_Raw_Headers<T> && Has_Get_Raw_Data<T>
               && Has_Get_Hash_Identifier<T> && Has_Hash_Sha_256<T>;

    template<typename T>
    concept Has_Total_Headers_Length = requires(const T t) {
        { T::total_headers_length } -> std::same_as<const size_t&>;
    };

    template<typename T>
    concept Has_Data_Length = requires(const T t) {
        { T::data_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Maximum length of compressed payload
     */
    template<typename T>
    concept Has_Max_Compressed_Data_Length = requires(const T t) {
        { T::max_compressed_data_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief CHK plus data. When fed a data::block::user::Chk, can decode into
     * the original data for a client.
     */
    template<typename T>
    concept Chk = Key<T> && Has_Total_Headers_Length<T> && Has_Data_Length<T>
               && Has_Max_Compressed_Data_Length<T>;

    /**
     * @brief how much of the headers we compare in order to consider
     * two SSKBlocks equal.
     *
     * @details
     * It's necessary because the last 64 bytes need not be
     * the same for the same data and the same key (see comments above)
     *
     */
    template<typename T>
    concept Has_Header_Compare_To = requires(const T t) {
        { T::header_compare_to } -> std::same_as<size_t>;
    };

    template<typename T>
    concept Has_Sig_R_Length = requires(const T t) {
        { T::sig_r_length } -> std::same_as<size_t>;
    };

    template<typename T>
    concept Has_Sig_S_Length = requires(const T t) {
        { T::sig_s_length } -> std::same_as<size_t>;
    };

    template<typename T>
    concept Has_E_H_Docname_Length = requires(const T t) {
        { T::e_h_docname_length } -> std::same_as<size_t>;
    };

    template<typename T>
    concept Has_Encrypted_Headers_Length = requires(const T t) {
        { T::encrypted_headers_length } -> std::same_as<size_t>;
    };

    /**
     * @brief SSK plus data.
     *
     * @details
     * Can do a node-level verification. Can decode original data when fed a
     * data::block::user::Ssk.
     *
     * HEADERS FORMAT:
     * 2 bytes - hash ID
     * 2 bytes - symmetric cipher ID
     * 32 bytes - E(H(docname))
     * ENCRYPTED WITH E(H(docname)) AS IV:
     *  32 bytes - H(decrypted data), = data decryption key
     *  2 bytes - data length + metadata flag
     *  2 bytes - data compression algorithm or -1
     * IMPLICIT - hash of data
     * IMPLICIT - hash of remaining fields, including the implicit hash of
     *  data
     *
     * SIGNATURE ON THE ABOVE HASH:
     *  32 bytes - signature: R (unsigned bytes)
     *  32 bytes - signature: S (unsigned bytes)
     *
     * PLUS THE PUBKEY:
     *  Pubkey
     *  Group
     *
     */
    template<typename T>
    concept Ssk = Key<T> && Has_Header_Compare_To<T> && Has_Data_Length<T>
               && Has_Max_Compressed_Data_Length<T> && Has_Sig_R_Length<T>
               && Has_Sig_S_Length<T> && Has_E_H_Docname_Length<T>
               && Has_Encrypted_Headers_Length<T>;

} // namespace concepts

namespace exception {
    class LIBHYPHANET_EXPORT Invalid_hash : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class LIBHYPHANET_EXPORT Invalid_signature : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class LIBHYPHANET_EXPORT Invalid_e_h_docname : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

} // namespace exception

static const size_t ssk_data_decrypt_key_length = 32;

/**
 * @brief Abstract class for fetched blocks.
 *
 * @details
 * Can be decoded by using a key::user::Key to
 * construct a block::user::Key, which can then be decoded to a
 * block::Bucket.
 */
class Key {
public:
    virtual ~Key() = default;

    [[nodiscard]] virtual std::shared_ptr<key::node::Key> get_node_key() const
    {
        return node_key_;
    }

    /**
     * Retrieves the raw headers of the Key.
     *
     * @return the raw headers as a vector of bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_raw_headers() const
    {
        return headers_;
    }

    /**
     * Retrieves the actual raw data of the Key.
     *
     * @return the raw data as a vector of bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_raw_data() const
    {
        return data_;
    }

    [[nodiscard]] virtual short get_hash_identifier() const
    {
        return hash_identifier_;
    }

    static const short hash_sha_256 = 1;

protected:
    Key(const std::vector<std::byte>& data,
        const std::vector<std::byte>& headers,
        const std::shared_ptr<key::node::Key>& node_key)
        : data_{data},
          headers_{headers},
          node_key_{node_key}
    {}

    void set_raw_headers(const std::vector<std::byte>& headers)
    {
        headers_ = headers;
    }

    void set_raw_data(const std::vector<std::byte>& data) { data_ = data; }

    void set_node_key(std::shared_ptr<key::node::Key> node_key)
    {
        node_key_ = std::move(node_key);
    }

    void set_hash_identifier(short id) { hash_identifier_ = id; }

private:
    std::vector<std::byte> data_;
    std::vector<std::byte> headers_;
    std::shared_ptr<key::node::Key> node_key_;
    short hash_identifier_{0};
};

/**
 * @brief CHK plus data. When fed a data::block::user::Chk, can decode into
 * the original data for a client.
 */
class Chk : public Key {
public:
    Chk(const std::vector<std::byte>& data,
        const std::vector<std::byte>& headers,
        const std::shared_ptr<key::node::Chk>& node_key = nullptr,
        bool verify = true,
        key::Crypto_algorithm algo =
            key::Crypto_algorithm::algo_aes_ctr_256_sha_256);

    [[nodiscard]] std::vector<std::byte> get_node_routing_key() const;
    [[nodiscard]] std::vector<std::byte> get_full_key() const;

    [[nodiscard]] std::vector<std::byte> get_pub_key() const { return {}; }

    static const size_t total_headers_length = 36;
    static const size_t data_length = 32768;
    static const size_t max_compressed_data_length = data_length - 4;
};

static_assert(concepts::Chk<Chk>);

/**
 * @brief SSK plus data.
 *
 * @details
 * Can do a node-level verification. Can decode original data when fed a
 * data::block::user::Ssk.
 *
 * HEADERS FORMAT:
 * 2 bytes - hash ID
 * 2 bytes - symmetric cipher ID
 * 32 bytes - E(H(docname))
 * ENCRYPTED WITH E(H(docname)) AS IV:
 *  32 bytes - H(decrypted data), = data decryption key
 *  2 bytes - data length + metadata flag
 *  2 bytes - data compression algorithm or -1
 * IMPLICIT - hash of data
 * IMPLICIT - hash of remaining fields, including the implicit hash of
 *  data
 *
 * SIGNATURE ON THE ABOVE HASH:
 *  32 bytes - signature: R (unsigned bytes)
 *  32 bytes - signature: S (unsigned bytes)
 *
 * PLUS THE PUBKEY:
 *  Pubkey
 *  Group
 *
 */
class Ssk : public Key {
public:
    Ssk(const std::vector<std::byte>& data,
        const std::vector<std::byte>& headers,
        const std::shared_ptr<key::node::Ssk>& node_key,
        bool verify);

    /**
     * @brief how much of the headers we compare in order to consider
     * two SSKBlocks equal.
     *
     * @details
     * It's necessary because the last 64 bytes need not be
     * the same for the same data and the same key (see comments above)
     *
     */
    static const size_t header_compare_to = 71;

    static const size_t data_length = 1024;

    /**
     * @brief Maximum length of compressed payload
     */
    static const size_t max_compressed_data_length = data_length - 2;

    static const size_t sig_r_length = 32;
    static const size_t sig_s_length = 32;
    static const size_t e_h_docname_length = 32;
    static const size_t encrypted_headers_length = 36;

    static const size_t total_headers_length = 2 + sig_r_length + sig_s_length
                                             + 2 + e_h_docname_length
                                             + ssk_data_decrypt_key_length;

private:
    /**
     * @brief The index of the first byte of encrypted fields in the
     * headers, after E(H(docname)).
     */
    size_t headers_offset_;

    std::vector<std::byte> pub_key_;

    short sym_cipher_identifier_{0};
};

// TODO: static_assert(concepts::Ssk<Ssk>);

} // namespace block::node

#endif /* LIBHYPHANET_BLOCK_NODE_H */
