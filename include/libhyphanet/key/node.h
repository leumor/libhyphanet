#ifndef LIBHYPHANET_KEY_NODE_H
#define LIBHYPHANET_KEY_NODE_H

#include "libhyphanet/key.h"

#include <cstddef>
#include <gsl/assert>
#include <libhyphanet/libhyphanet_export.h>
#include <memory>
#include <vector>

namespace key::node {

namespace concepts {
    /**
     * @brief Get the full key.
     *
     * @details
     * Including any crypto type bytes, everything needed to construct a Key
     * object.
     *
     * @return std::vector<std::byte> the full key bytes.
     */
    template<typename T>
    concept Has_Get_Full_Key = requires(const T t) {
        { t.get_full_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Get a copy of the key with any unnecessary information
     * stripped, for long-term in-memory storage.
     *
     * @details
     * E.g. for SSKs, strips the DSAPublicKey. Copies it whether
     * we need to copy it because the original might pick up a pubkey after
     * this call. And the returned key will not accidentally pick up extra
     * data.
     *
     * @return Key the copy of the key.
     */
    template<typename T, typename U>
    concept Has_Archival_Copy = requires(const T t) {
        { t.archival_copy() } -> std::same_as<std::unique_ptr<U>>;
    };

    /**
     * @brief Get key type
     *
     * @details
     * - High 8 bit (```(type >> 8) & 0xFF```) is the base type
     * (Chk#base_type} or {Ssk#base_type).
     * - Low 8 bit (```type & 0xFF```) is the crypto algorithm. (Currently
     * only Crypto_algorithm::algo_aes_pcfb_256_sha_256 is supported).
     *
     * @return short the key type.
     */
    template<typename T>
    concept Has_Get_Type = requires(const T t) {
        { t.get_type() } -> std::same_as<short>;
    };

    /**
     * @brief Get the key bytes.
     *
     * @details
     * Not just the routing key, enough data to reconstruct the key
     * (excluding any pubkey needed).
     *
     * @return std::vector<std::byte> the key bytes.
     */
    template<typename T>
    concept Has_Get_Key_Bytes = requires(const T t) {
        { t.get_key_bytes() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Has_To_Normalized_Double = requires(T t) {
        { t.to_normalized_double() } -> std::same_as<double>;
    };

    template<typename T>
    concept Has_Get_Node_Routing_Key = requires(const T t) {
        {
            t.get_node_routing_key()
        } -> std::same_as<const std::vector<std::byte>&>;
    };

    template<typename T>
    concept Has_Get_Crypto_Algorithm = requires(const T t) {
        { t.get_crypto_algorithm() } -> std::same_as<Crypto_algorithm>;
    };

    /**
     * @brief Base class for node keys.
     */
    template<typename T>
    concept Base_Key
        = Has_Get_Full_Key<T> && Has_Get_Type<T> && Has_Get_Key_Bytes<T>
          && Has_To_Normalized_Double<T> && Has_Get_Node_Routing_Key<T>
          && Has_Get_Crypto_Algorithm<T>;

    template<typename T, typename U>
    concept Key = Base_Key<T> && Base_Key<U> && Has_Archival_Copy<T, U>;

    template<typename T>
    concept Has_Base_Type = requires {
        { T::base_type } -> std::same_as<const std::byte&>;
    };

    template<typename T>
    concept Has_Key_Length = requires {
        { T::key_length } -> std::same_as<const size_t&>;
    };

    template<typename T>
    concept Has_Full_Key_Length = requires {
        { T::full_key_length } -> std::same_as<const size_t&>;
    };

    template<typename T, typename U>
    concept Chk = Key<T, U> && Has_Base_Type<T> && Has_Key_Length<T>
                  && Has_Full_Key_Length<T>;

    template<typename T>
    concept Has_Get_Encrypted_Hashed_Docname = requires(const T t) {
        {
            t.get_encrypted_hashed_docname()
        } -> std::same_as<std::array<std::byte, 32>>;
    };

    template<typename T>
    concept Has_Get_Pub_Key = requires(const T t) {
        { t.get_pub_key() } -> std::same_as<std::vector<std::byte>>;
    };

    template<typename T>
    concept Has_Ssk_Version = requires {
        { T::ssk_version } -> std::same_as<const std::byte&>;
    };

    template<typename T, typename U>
    concept Ssk
        = Key<T, U> && Has_Get_Encrypted_Hashed_Docname<T> && Has_Get_Pub_Key<T>
          && Has_Ssk_Version<T> && Has_Base_Type<T> && Has_Full_Key_Length<T>;

} // namespace concepts

/**
 * @brief Base class for node keys.
 */
class LIBHYPHANET_EXPORT Key {
public:
    virtual ~Key() = default;

    [[nodiscard]] virtual short get_type() const = 0;
    [[nodiscard]] virtual std::vector<std::byte> get_full_key() const = 0;

    /**
     * @brief Get the key bytes.
     *
     * @details
     * Not just the routing key, enough data to reconstruct the key
     * (excluding any pubkey needed).
     *
     * @return std::vector<std::byte> the key bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_key_bytes() const
    {
        return node_routing_key_;
    }

    [[nodiscard]] virtual double to_normalized_double();

    [[nodiscard]] virtual const std::vector<std::byte>&
    get_node_routing_key() const
    {
        return node_routing_key_;
    }

    [[nodiscard]] virtual Crypto_algorithm get_crypto_algorithm() const
    {
        return crypto_algorithm_;
    }

protected:
    explicit Key(Crypto_algorithm algo)
        : crypto_algorithm_(algo)
    {}

    Key(const std::vector<std::byte>& node_routing_key, Crypto_algorithm algo)
        : node_routing_key_(node_routing_key),
          crypto_algorithm_(algo)
    {
        Expects(!node_routing_key_.empty());
    }

    void set_node_routing_key(const std::vector<std::byte>& node_routing_key)
    {
        Expects(!node_routing_key.empty());
        node_routing_key_ = node_routing_key;
    }

private:
    /**
     * @brief Node Routing Key.
     *
     * @details
     * The **Node Routing Key** is based on the hash of the data or the
     * public key of the owner ([Client Routing
     * Key](#user::Key#routing_key_)), and it determines how close a node is
     * to the data. Nodes use the routing key to forward requests to the
     * node that is most responsible for storing the data, or the closest
     * one they know of.
     *
     * For [CHKs](#user::Chk), the **Node Routing Key** is the [Client
     * Routing Key](#user::Key#routing_key_).
     *
     * For [Subspace Keys](#user::Subspace_key), **Node Routing Key** is a
     * SHA-256 hash of the [Encrypted Hashed Document
     * Name](#user::Ssk#encrypted_hashed_docname_) and the [Client Routing
     * Key](#user::Key#routing_key_).
     */
    std::vector<std::byte> node_routing_key_;

    /**
     * @brief The cryptographic algorithm used for encryption/decryption.
     */
    Crypto_algorithm crypto_algorithm_{
        Crypto_algorithm::algo_aes_ctr_256_sha_256
    };

    double cached_normalized_double_{-1.0};
};

class LIBHYPHANET_EXPORT Chk : public Key {
public:
    Chk(const std::vector<std::byte>& node_routing_key, Crypto_algorithm algo)
        : Key{node_routing_key, algo}
    {}

    [[nodiscard]] std::vector<std::byte> get_full_key() const override;
    [[nodiscard]] std::unique_ptr<Chk> archival_copy() const;
    [[nodiscard]] short get_type() const override;

    static const std::byte base_type = std::byte{1};
    static const size_t key_length = 32;
    static const size_t full_key_length = 34;
};

static_assert(concepts::Chk<Chk, Chk>);

class LIBHYPHANET_EXPORT Ssk : public Key {
public:
    Ssk(const std::vector<std::byte>& user_routing_key,
        const std::array<std::byte, 32>& encrypted_hashed_docname,
        Crypto_algorithm algo = Crypto_algorithm::algo_aes_ctr_256_sha_256,
        std::vector<std::byte> pub_key = {});

    [[nodiscard]] std::vector<std::byte> get_full_key() const override;
    [[nodiscard]] virtual std::unique_ptr<Ssk> archival_copy() const;
    [[nodiscard]] short get_type() const override;
    [[nodiscard]] std::vector<std::byte> get_key_bytes() const override;

    [[nodiscard]] std::array<std::byte, 32> get_encrypted_hashed_docname() const
    {
        return encrypted_hashed_docname_;
    }

    [[nodiscard]] std::vector<std::byte> get_pub_key() const
    {
        return pub_key_;
    }

    static const std::byte ssk_version = std::byte{1};
    static const std::byte base_type = std::byte{2};
    static const size_t full_key_length = 66;

private:
    [[nodiscard]] static std::vector<std::byte> make_routing_key(
        const std::vector<std::byte>& user_routing_key,
        const std::array<std::byte, 32>& encrypted_hashed_docname
    );

    std::array<std::byte, 32> user_routing_key_;
    std::array<std::byte, 32> encrypted_hashed_docname_{};
    std::vector<std::byte> pub_key_;
};

class LIBHYPHANET_EXPORT Archive_ssk : public Ssk {
public:
    Archive_ssk(
        const std::vector<std::byte>& user_routing_key,
        const std::array<std::byte, 32>& encrypted_hashed_docname,
        Crypto_algorithm algo = Crypto_algorithm::algo_aes_ctr_256_sha_256
    )
        : Ssk{user_routing_key, encrypted_hashed_docname, algo}
    {}
};

static_assert(concepts::Ssk<Ssk, Ssk> && concepts::Ssk<Archive_ssk, Ssk>);

} // namespace key::node

#endif /* LIBHYPHANET_KEY_NODE_H */
