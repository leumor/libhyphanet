#ifndef LIBHYPHANET_BLOCK_NODE_H
#define LIBHYPHANET_BLOCK_NODE_H

#include "libhyphanet/key/node.h"
#include "libhyphanet/support.h"

#include <cstddef>
#include <libhyphanet/libhyphanet_export.h>
#include <vector>

namespace block::node {

namespace concepts {
    /**
     * @brief Concept for types that provide a node routing key.
     *
     * @details
     * Types satisfying this concept must provide a method to retrieve their
     * node routing key, which is used to locate and request data blocks on the
     * network.
     *
     * The node routing key is used for routing messages in the Freenet
     * network. It's typically derived from the hash of the data or the public
     * key of the owner ([Client Routing Key](#user::Key#routing_key_)).
     *
     * @see
     * [Node Routing Key](#key::node::Key#node_routing_key_)
     */
    template<typename T>
    concept Has_Get_Node_Routing_Key = requires(const T t) {
        { t.get_node_routing_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Concept for types that provide a full key.
     *
     * @details
     * The full key including any crypto type bytes, everything needed to
     * construct a [Node Key](#key::node::Key) object.
     */
    template<typename T>
    concept Has_Get_Full_Key = requires(const T t) {
        { t.get_full_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Concept for types that can be stored in the Freenet network.
     *
     * @details
     * Storable types must provide both a node routing key for network
     * operations and a full key for complete block retrieval and decoding.
     */
    template<typename T>
    concept Storable = Has_Get_Node_Routing_Key<T> && Has_Get_Full_Key<T>;

    /**
     * @brief Concept for types that provide a public key.
     *
     * @details
     * This is primarily used for SSK (Signed Subspace Key) blocks,
     * where the public key is used to verify the block's signature.
     */
    template<typename T>
    concept Has_Get_Pub_Key = requires(const T t) {
        { t.get_pub_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Concept for types that provide raw headers.
     *
     * @details
     * Raw headers contain metadata about the block, such as its type,
     * encryption details, and other format-specific information.
     */
    template<typename T>
    concept Has_Get_Raw_Headers = requires(const T t) {
        { t.get_raw_headers() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Concept for types that provide raw data.
     *
     * @details
     * Raw data is the actual content of the block, which may be
     * encrypted or compressed depending on the block type.
     */
    template<typename T>
    concept Has_Get_Raw_Data = requires(const T t) {
        { t.get_raw_data() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Concept for types that provide a hash identifier.
     *
     * @details
     * The hash identifier specifies which hash algorithm is used
     * for this block, typically SHA-256 in modern Freenet implementations.
     */
    template<typename T>
    concept Has_Get_Hash_Identifier = requires(const T t) {
        { t.get_hash_identifier() } -> std::same_as<short>;
    };

    /**
     * @brief Concept for types that have a static SHA-256 hash value.
     *
     * @details
     * This concept ensures that the type has a consistent SHA-256
     * hash identifier, which is crucial for maintaining compatibility
     * across the network.
     */
    template<typename T>
    concept Has_Hash_Sha_256 = requires(const T t) {
        { T::hash_sha_256 } -> std::same_as<const short&>;
    };

    /**
     * @brief Concept for node key block types.
     *
     * @details
     * This concept aggregates multiple requirements for a complete node key
     * block implementation. It ensures that a node key block type can be
     * stored, provides necessary cryptographic information, and includes all
     * required metadata for block handling in the Freenet network.
     *
     * It can be decoded by using a key::user::Key to
     * construct a block::user::Key, which can then be decoded to a
     * block::Bucket.
     */
    template<typename T>
    concept Key = Storable<T> && Has_Get_Pub_Key<T> && Has_Get_Raw_Headers<T>
               && Has_Get_Raw_Data<T> && Has_Get_Hash_Identifier<T>
               && Has_Hash_Sha_256<T>;

    /**
     * @brief Concept for shared pointers to key block types.
     *
     * @details
     * This concept ensures that a shared pointer points to a type
     * that satisfies the Key concept, allowing for safe shared ownership
     * of key block objects.
     */
    template<typename T>
    concept Key_Shared_Ptr =
        support::concepts::Shared_Ptr<T> && Key<typename T::element_type>;

    /**
     * @brief Concept for types with a total headers length.
     *
     * @details
     * This specifies the total length of the headers in a block,
     * which is crucial for parsing and validating block structures.
     */
    template<typename T>
    concept Has_Total_Headers_Length = requires(const T t) {
        { T::total_headers_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with a data length.
     *
     * @details
     * This specifies the length of the actual data content in a block,
     * which is important for data retrieval and storage operations.
     */
    template<typename T>
    concept Has_Data_Length = requires(const T t) {
        { T::data_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with a maximum compressed data length.
     *
     * @details
     * This specifies the maximum payload length of compressed data in a block.
     */
    template<typename T>
    concept Has_Max_Compressed_Data_Length = requires(const T t) {
        { T::max_compressed_data_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for CHK (Content Hash Key) Block types.
     *
     * @details
     * Node CHK plus data. When fed a key::user::Chk, can decode into
     * the original data for a client.
     */
    template<typename T>
    concept Chk = Key<T> && Has_Total_Headers_Length<T> && Has_Data_Length<T>
               && Has_Max_Compressed_Data_Length<T>;

    /**
     * @brief Concept for types with a header comparison length.
     *
     * @details
     * This specifies how much of the headers should be compared when
     * determining if two blocks are equal. It's particularly important for SSK
     * blocks.
     */
    template<typename T>
    concept Has_Header_Compare_To = requires(const T t) {
        { T::header_compare_to } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with a signature R length.
     *
     * @details
     * Part of the DSA signature used in SSK blocks. The 'r' value
     * in the DSA signature algorithm.
     */
    template<typename T>
    concept Has_Sig_R_Length = requires(const T t) {
        { T::sig_r_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with a signature S length.
     *
     * @details
     * Part of the DSA signature used in SSK blocks. The 's' value
     * in the DSA signature algorithm.
     */
    template<typename T>
    concept Has_Sig_S_Length = requires(const T t) {
        { T::sig_s_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with an encrypted hashed docname length.
     *
     * @details
     * Used in SSK blocks to specify the length of the encrypted
     * and hashed document name, which is part of the SSK structure.
     */
    template<typename T>
    concept Has_E_H_Docname_Length = requires(const T t) {
        { T::e_h_docname_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for types with an encrypted headers length.
     *
     * @details
     * Specifies the length of the encrypted headers in SSK blocks,
     * which contain additional metadata about the block.
     */
    template<typename T>
    concept Has_Encrypted_Headers_Length = requires(const T t) {
        { T::encrypted_headers_length } -> std::same_as<const size_t&>;
    };

    /**
     * @brief Concept for SSK (Signed Subspace Key) block types.
     *
     * @details
     * SSK plus data.
     *
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

[[nodiscard]] LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
get_node_key(concepts::Key auto& block_node_key)
{
    return block_node_key.get_node_key();
}

static const size_t ssk_data_decrypt_key_length = 32;

/**
 * @brief Abstract class for fetched blocks.
 *
 * @details
 * Can be decoded by using a key::user::Key to
 * construct a block::user::Key, which can then be decoded to a
 * block::Bucket.
 *
 * See KeyBlock in Java code.
 */
class Key {
public:
    virtual ~Key() = default;

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
        const std::vector<std::byte>& headers)
        : data_{data},
          headers_{headers}
    {}

    void set_raw_headers(const std::vector<std::byte>& headers)
    {
        headers_ = headers;
    }

    void set_raw_data(const std::vector<std::byte>& data) { data_ = data; }

    void set_hash_identifier(short id) { hash_identifier_ = id; }

private:
    std::vector<std::byte> data_;
    std::vector<std::byte> headers_;
    short hash_identifier_{0};
};

/**
 * @brief CHK plus data. When fed a data::block::user::Chk, can decode into
 * the original data for a client.
 */
class Chk : public Key {
public:
    friend LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
    get_node_key(concepts::Key auto& block_node_key);

    Chk(const std::vector<std::byte>& data,
        const std::vector<std::byte>& headers,
        const std::shared_ptr<key::node::Chk>& node_key = nullptr,
        bool verify = true,
        key::Crypto_algorithm algo =
            key::Crypto_algorithm::algo_aes_ctr_256_sha_256);

    [[nodiscard]] std::vector<std::byte> get_node_routing_key() const;
    [[nodiscard]] std::vector<std::byte> get_full_key() const;

    [[nodiscard]] static std::vector<std::byte> get_pub_key() { return {}; }

    static const size_t total_headers_length = 36;
    static const size_t data_length = 32768;
    static const size_t max_compressed_data_length = data_length - 4;

private:
    [[nodiscard]] std::shared_ptr<key::node::Chk> get_node_key() const
    {
        return node_key_;
    }

    void set_node_key(const std::shared_ptr<key::node::Chk>& node_key)
    {
        node_key_ = node_key;
    }

    std::shared_ptr<key::node::Chk> node_key_;
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
    friend LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
    get_node_key(concepts::Key auto& block_node_key);

    Ssk(const std::vector<std::byte>& data,
        const std::vector<std::byte>& headers,
        const std::shared_ptr<key::node::Ssk>& node_key,
        bool verify);

    [[nodiscard]] std::vector<std::byte> get_node_routing_key() const;

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

    [[nodiscard]] std::vector<std::byte> get_full_key() const
    {
        return get_node_key()->get_full_key();
    }

    [[nodiscard]] std::vector<std::byte> get_pub_key() const
    {
        return pub_key_;
    }

private:
    [[nodiscard]] std::shared_ptr<key::node::Ssk> get_node_key() const
    {
        return node_key_;
    }

    void set_node_key(const std::shared_ptr<key::node::Ssk>& node_key)
    {
        node_key_ = node_key;
    }

    std::shared_ptr<key::node::Ssk> node_key_;

    /**
     * @brief The index of the first byte of encrypted fields in the
     * headers, after E(H(docname)).
     */
    size_t headers_offset_;

    std::vector<std::byte> pub_key_;

    short sym_cipher_identifier_{0};
};

static_assert(concepts::Ssk<Ssk>);

} // namespace block::node

#endif /* LIBHYPHANET_BLOCK_NODE_H */
