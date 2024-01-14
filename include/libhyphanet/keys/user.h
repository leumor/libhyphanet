#ifndef LIBHYPHANET_KEYS_USER_H
#define LIBHYPHANET_KEYS_USER_H

#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cstddef>
#include <gsl/assert>
#include <gsl/gsl>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace keys::user {
/**
 * @brief Pure Virtual Class for user keys that can be converted to a
 * [URI](#Uri).
 *
 * @details
 * There are currently two types of user keys:
 *
 * - Client Key: Client keys are decodable. The client key generally
 *               contains the encryption keys which the node level does not
 *               know about, but which are in the URI - usually the second
 *               part, after the comma.
 * - Non Client Key: Things like USK, which don't directly translate to a
 *                   routing key. But it usually can be converted to a
 *                   ClientKey by some algorithm.
 */
class Key {
public:
    enum class Crypto_algorithm {
        /**
         * AES-256 with
         * [PCFB](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/pcfb/pcfb-spec.pdf)
         * (Propagating Cipher Feedback) mode, SHA-256 hashing.
         */
        algo_aes_pcfb_256_sha_256 = 2,
        /**
         * AES-256 with CTR (Counter) mode, SHA-256 hashing.
         */
        algo_aes_ctr_256_sha_256 = 3,
    };

    struct Key_params {
        std::vector<std::byte> routing_key;
        std::vector<std::byte> crypto_key;
        Crypto_algorithm crypto_algorithm;
    };

    explicit Key(Key_params key)
        : routing_key_(std::move(key.routing_key)),
          crypto_key_(std::move(key.crypto_key)),
          crypto_algorithm_(key.crypto_algorithm)
    {}

    explicit Key(const Uri& uri);

    Key() = default;
    Key(const Key& other) = default;
    Key(Key&& other) noexcept = default;
    Key& operator=(const Key& other) = default;
    Key& operator=(Key&& other) noexcept = default;
    virtual ~Key() = default;

    [[nodiscard]] virtual std::string to_uri() const = 0;

    [[nodiscard]] static std::unique_ptr<Key> create_from_uri(const Uri& uri);

    [[nodiscard]] std::vector<std::byte> get_routing_key() const
    {
        return routing_key_;
    }

    [[nodiscard]] std::vector<std::byte> get_crypto_key() const
    {
        return crypto_key_;
    }

    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const
    {
        return crypto_algorithm_;
    }

    static const size_t crypto_key_length = 32;
    static const size_t extra_length = 5;
protected:
    void set_routing_key(std::vector<std::byte> key)
    {
        routing_key_ = std::move(key);
    }
    void set_crypto_key(std::vector<std::byte> key)
    {
        crypto_key_ = std::move(key);
    }
    void set_crypto_algorithm(Crypto_algorithm algo)
    {
        crypto_algorithm_ = algo;
    }
private:
    /**
     * @brief Client Routing key.
     *
     * @details
     * Client Routing key is a part of the Freenet URI (address) that
     * is used to generate a [Node Routing
     * Key](#node::Node_key#node_routing_key_) which can later be used to
     * locate and request data blocks on the network.
     *
     * The hash itself is calculated differently depending on the key type.
     */
    std::vector<std::byte> routing_key_;

    /**
     * @brief The encryption key.
     *
     * @details
     * A encryption key is a part of the Freenet URI (address) that is used
     * to decrypt the data once it is downloaded.The encryption key is
     * usually randomly generated and not related to the routing key. The
     * node that stores the data only knows the routing key, and cannot
     * decrypt the data without the encryption key.
     *
     */
    std::vector<std::byte> crypto_key_;

    /**
     * @brief Algorithm used to encrypt the data
     *
     * @details
     * Currently only AES-CTR and AES-PCFB are supported.
     *
     * @sa [Crypto_algorithm](#Key::Crypto_algorithm)
     *
     */
    Crypto_algorithm crypto_algorithm_{
        Crypto_algorithm::algo_aes_pcfb_256_sha_256};
};

/**
 * @brief A mixin class for Client Keys.
 *
 * @details
 * Client keys are decodable. Node keys are not. When data has been fetched
 * to a node-level Key Block, it can only be decoded after a Client Key
 * Block has been constructed from the node-level block and the client key.
 * The client key generally contains the encryption keys which the node
 * level does not know about, but which are in the URI - usually the second
 * part, after the comma.
 */
class Client {
public:
    Client() = default;
    Client(const Client& other) = default;
    Client(Client&& other) noexcept = default;
    Client& operator=(const Client& other) = default;
    Client& operator=(Client&& other) noexcept = default;
    virtual ~Client() = default;

    /**
     * @brief Return the node key corresponding to this key.
     */
    [[nodiscard]] virtual node::Node_key get_node_key() const = 0;
};

/**
 * @brief A mixin class for Insertable Keys.
 *
 * @details
 * A Insertable key contains a private key from the [Key](#Key) owner, so
 * a user can use it to insert new versions of data.
 */
class Insertable {
public:
    Insertable() = default;
    explicit Insertable(const CryptoPP::DSA::PrivateKey& priv_key)
        : priv_key_(priv_key)
    {}

    /**
     * @brief Return the private key for current [Key](#Key).
     */
    CryptoPP::DSA::PrivateKey get_priv_key() const { return priv_key_; }

    virtual ~Insertable() = 0;
private:
    /**
     * @brief Private key for current [Key](#Key)
     *
     * @details
     * It can be used to encrypt and sign the data for current [Key](#Key).
     * Once signed, the data can be inserted into the network.
     *
     */
    CryptoPP::DSA::PrivateKey priv_key_;
};

/**
 * @brief Subspace Key is a subtype of [Key](#Key) that encoded a
 * [document name](#doc_name_) into it.
 *
 * @details
 * The [document name](#doc_name_) will later be used to generate a [routing
 * key](#node::Node_key#routing_key_).
 *
 */
class Subspace_key : public Key {
public:
    Subspace_key(Key_params key, std::string_view docname)
        : Key{std::move(key)}, docname_(docname)
    {}

    explicit Subspace_key(const Uri& uri);

    Subspace_key() = default;
    Subspace_key(const Subspace_key& other) = default;
    Subspace_key(Subspace_key&& other) noexcept = default;
    Subspace_key& operator=(const Subspace_key& other) = default;
    Subspace_key& operator=(Subspace_key&& other) noexcept = default;
    ~Subspace_key() override = 0;

    [[nodiscard]] std::string get_docname() const { return docname_; }

    static const size_t routing_key_size
        = 32; // TODO: same as Node_ssk::pubkey_hash_size
protected:
    void set_docname(std::string_view docname) { docname_ = docname; }
private:
    /**
     * @brief Document name.
     *
     * @details
     * A docname (sometimes called site name) is a part of the address that
     * provides a human-readable name for the file. It will later be used to
     * generate a [Node Routing Key](#node::Node_key#node_routing_key_).
     *
     * @sa
     * - [Ssk#encrypted_hashed_docname_](#Ssk#encrypted_hashed_docname_)
     * - [Key#routing_key_](#Key#routing_key_)
     * - [Key#crypto_key_](#Key#crypto_key_)
     */
    std::string docname_;
};

/**
 * @brief Updatable Subspace Key (**USK**).
 *
 * @details
 * A special type of key that implements a crude updating scheme at the
 * client level. It allows the user to request the latest version of a file
 * without knowing the exact **SSK**. Example:
 *
 * ```
 * freenet:USK@~Alice/MyBlog/2024-01-02.html/5
 * ```
 *
 * It isn't really a [Client_Key](#Client_key) as it cannot be directly
 * requested.
 *
 * It contains:
 * - Enough information to produce a real SSK.
 * - Site name.
 * - Site edition number.
 */
class Usk : public Subspace_key {
public:
    Usk(Key_params key, std::string_view docname, long suggested_edition = -1)
        : Subspace_key{std::move(key), docname},
          suggested_edition_(suggested_edition)
    {}

    explicit Usk(const Uri& uri);

    Usk() = default;
    Usk(const Usk& other) = default;
    Usk(Usk&& other) noexcept = default;
    Usk& operator=(const Usk& other) = default;
    Usk& operator=(Usk&& other) noexcept = default;
    ~Usk() override = default;

    [[nodiscard]] std::string to_uri() const override;
private:
    /**
     * @brief The character to separate the site name from the edition
     * number in its SSK form.
     *
     * @details
     * The reason for choosing '-' is that it makes it ludicrously easy
     * to go from the **USK** form to the **SSK** form, and we don't
     * need to go vice versa.
     */
    static const auto seperator = '-';

    /**
     * @brief Suggestion edition.
     *
     * @details
     * A suggestion edition in **USK** allows the user to request
     * the latest version of a file without knowing the exact
     * **[SSK](#Ssk)** of the file. It is a number that is appended to the
     * USK after a slash, such as
     * `freenet:USK@~Alice/MyBlog/2024-01-02.html/5`. It tells the client
     * which edition of the file to start looking for. If the client finds a
     * newer edition, it will automatically switch to it. The suggestion
     * edition can be updated manually by the user, or automatically by the
     * client.
     *
     * The suggestion edition in **USK** is useful for creating dynamic
     * content on Freenet, such as blogs, forums, or wikis. It allows the
     * owner of the file to update the content with a new **[SSK](#Ssk)**,
     * and the users to access the updated content with the same **USK**.
     * It also helps to reduce the network load, as the client does not have
     * to search for all possible editions of the file.
     *
     * `-1` in suggest edition means that the client will try to
     * find the highest edition number available for the file, starting from
     * zero and incrementing by one until it fails. This way, the user can
     * always get the most recent version of the file without knowing the
     * exact edition number.
     */
    long suggested_edition_{-1};
};

class Insertable_usk : public Usk, public Insertable {
public:
    Insertable_usk(Usk usk, const CryptoPP::DSA::PrivateKey& priv_key)
        : Usk(std::move(usk)), Insertable(priv_key)
    {}

    /**
     * @brief Create a from uri object.
     *
     * @details
     * A new private/public key pair will be generated. The crypto_key and
     * docname from the uri will be kept.
     *
     * @param uri
     * @return std::unique_ptr<Insertable_usk>
     */
    static std::unique_ptr<Insertable_usk>
    create_insertable_from_uri(const Uri& uri);
};

class Ssk : public Subspace_key, public Client {
public:
    Ssk(Key_params key, std::string_view docname);

    explicit Ssk(const Uri& uri);

    Ssk() = default;
    Ssk(const Ssk& other) = default;
    Ssk(Ssk&& other) noexcept = default;
    Ssk& operator=(const Ssk& other) = default;
    Ssk& operator=(Ssk&& other) noexcept = default;
    ~Ssk() override = default;

    [[nodiscard]] std::string to_uri() const override;
    [[nodiscard]] node::Node_key get_node_key() const override;
private:
    std::vector<std::byte> encrypted_hashed_docname_;
};

class Insertable_ssk : public Ssk, public Insertable {
public:
    Insertable_ssk() = default;
    Insertable_ssk(Key_params key, std::string_view docname,
                   const CryptoPP::DSA::PrivateKey& priv_key)
        : Ssk{std::move(key), docname}, Insertable(priv_key)
    {}

    Insertable_ssk(Ssk ssk, const CryptoPP::DSA::PrivateKey& priv_key)
        : Ssk(std::move(ssk)), Insertable(priv_key)
    {}
};

class Ksk : public Insertable_ssk {
public:
    explicit Ksk(std::string keyword);
    explicit Ksk(const Uri& uri);

    Ksk() = default;
private:
    std::string keyword_;
};

class Chk : public Key, public Client {
public:
    Chk(Key_params key, bool control_document,
        support::compressor::Compress_type compression_algorithm)
        : Key(std::move(key)), control_document_(control_document),
          compression_algorithm_(compression_algorithm)
    {}
    explicit Chk(const Uri& uri);

    Chk() = default;

    [[nodiscard]] std::string to_uri() const override;
    [[nodiscard]] node::Node_key get_node_key() const override;

    static const short routing_key_length = 32;
private:
    bool control_document_{false};
    support::compressor::Compress_type compression_algorithm_{
        support::compressor::Compress_type::gzip};
};

} // namespace keys::user

#endif /* LIBHYPHANET_KEYS_USER_H */
