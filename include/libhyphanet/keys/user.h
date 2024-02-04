#ifndef LIBHYPHANET_KEYS_USER_H
#define LIBHYPHANET_KEYS_USER_H

#include "libhyphanet/keys.h"
#include "libhyphanet/support.h"
#include <array>
#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cstddef>
#include <gsl/assert>
#include <gsl/gsl>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
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
protected:
    class Token {};
    friend class Insertable;
public:
    // Remmember to also modify valid_crypto_algorithms if you change this
    enum class Crypto_algorithm : std::underlying_type_t<std::byte> {
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
    static constexpr std::array<std::byte, 2> valid_crypto_algorithms{
        std::byte{2}, std::byte{3}};

    struct Key_params {
        std::vector<std::byte> routing_key;
        std::array<std::byte, crypto_key_length> crypto_key;
        Crypto_algorithm crypto_algorithm;
        std::vector<std::string> meta_strings;
    };

    explicit Key(Key_params key)
        : routing_key_(std::move(key.routing_key)), crypto_key_(key.crypto_key),
          crypto_algorithm_(key.crypto_algorithm),
          meta_strings_(key.meta_strings)
    {
        check_invariants();
    }

    explicit Key(Token /*unused*/) {}
    Key() = delete;
    Key(const Key& other) = default;
    Key(Key&& other) noexcept = default;
    Key& operator=(const Key& other) = default;
    Key& operator=(Key&& other) noexcept = default;
    virtual ~Key() = default;

    [[nodiscard]] virtual Uri to_uri() const = 0;

    [[nodiscard]] static std::unique_ptr<Key> create(const Uri& uri);

    [[nodiscard]] std::vector<std::byte> get_routing_key() const
    {
        return routing_key_;
    }

    [[nodiscard]] std::array<std::byte, crypto_key_length>
    get_crypto_key() const
    {
        return crypto_key_;
    }

    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const
    {
        return crypto_algorithm_;
    }

    [[nodiscard]] const std::vector<std::string>& get_meta_strings() const
    {
        return meta_strings_;
    }
protected:
    virtual void init_from_uri(const Uri& uri);

    virtual void set_routing_key(std::vector<std::byte> key)
    {
        routing_key_ = std::move(key);
    }
    void set_crypto_key(const std::array<std::byte, crypto_key_length>& key)
    {
        crypto_key_ = key;
    }
    void set_crypto_algorithm(Crypto_algorithm algo)
    {
        crypto_algorithm_ = algo;
    }
    void set_meta_strings(const std::vector<std::string>& meta_strings)
    {
        meta_strings_ = meta_strings;
    }

    std::optional<std::string> pop_meta_strings();
private:
    void check_invariants() const;

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
    std::array<std::byte, crypto_key_length> crypto_key_{};

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

    std::vector<std::string> meta_strings_;
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
    explicit Insertable(const std::vector<std::byte>& priv_key)
        : priv_key_{priv_key}
    {}

    explicit Insertable(Key::Token /*unused*/) {}
    Insertable() = delete;
    virtual ~Insertable() = 0;

    /**
     * @brief Return the private key for current [Key](#Key).
     */
    [[nodiscard]] std::vector<std::byte> get_priv_key() const
    {
        return priv_key_;
    }
protected:
    void set_priv_key(std::vector<std::byte> key)
    {
        priv_key_ = std::move(key);
    }
private:
    /**
     * @brief Private key for current [Key](#Key)
     *
     * @details
     * It can be used to encrypt and sign the data for current [Key](#Key).
     * Once signed, the data can be inserted into the network.
     *
     */
    std::vector<std::byte> priv_key_;
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
    {
        check_invariants();

        // SSK always uses algo_aes_pcfb_256_sha_256
        set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);

        get_routing_key().reserve(routing_key_size);
    }

    explicit Subspace_key(Token t): Key{t} {}
    Subspace_key() = delete;
    Subspace_key(const Subspace_key& other) = default;
    Subspace_key(Subspace_key&& other) noexcept = default;
    Subspace_key& operator=(const Subspace_key& other) = default;
    Subspace_key& operator=(Subspace_key&& other) noexcept = default;
    ~Subspace_key() override = 0;

    [[nodiscard]] std::string get_docname() const { return docname_; }

    [[nodiscard]] Uri to_uri() const override;

    static const size_t routing_key_size
        = 32; // TODO: same as Node_ssk::pubkey_hash_size
    static const size_t extra_length = 5;
protected:
    void init_from_uri(const Uri& uri) override;

    [[nodiscard]] virtual std::vector<std::byte> get_extra_bytes() const;
    void set_docname(std::string_view docname) { docname_ = docname; }
private:
    void check_invariants() const;

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

class Usk;

class Ssk : public Subspace_key, public Client {
public:
    /**
     * @brief The character to separate the site name from the edition
     * number in its SSK form.
     *
     * @details
     * The reason for choosing '-' is that it makes it ludicrously easy
     * to go from the **USK** form to the **SSK** form, and we don't
     * need to go vice versa.
     */
    static constexpr auto seperator = '-';

    Ssk(Key_params key, std::string_view docname,
        const std::optional<const std::vector<std::byte>>& pub_key
        = std::nullopt)
        : Subspace_key{std::move(key), docname}, pub_key_{pub_key}
    {
        calculate_encrypted_hashed_docname();
        check_invariants();
    }

    explicit Ssk(Token t): Subspace_key{t} {}
    Ssk() = delete;
    Ssk(const Ssk& other) = default;
    Ssk(Ssk&& other) noexcept = default;
    Ssk& operator=(const Ssk& other) = default;
    Ssk& operator=(Ssk&& other) noexcept = default;
    ~Ssk() override = default;

    [[nodiscard]] Uri to_uri() const override;

    [[nodiscard]] std::optional<Usk> to_usk() const;

    [[nodiscard]] node::Node_key get_node_key() const override;

    void set_pub_key(const std::vector<std::byte>& pub_key);

    [[nodiscard]] std::optional<std::vector<std::byte>> get_pub_key() const
    {
        return pub_key_;
    }
protected:
    void init_from_uri(const Uri& uri) override;
private:
    void calculate_encrypted_hashed_docname();

    void check_invariants() const;

    [[nodiscard]] static std::array<std::byte, 32>
    calculate_pub_key_hash(const std::vector<std::byte>& pub_key);

    [[nodiscard]] std::optional<std::pair<std::string, long>>
    parse_sitename_edition() const;

    std::array<std::byte, 32> encrypted_hashed_docname_{};

    std::optional<std::vector<std::byte>> pub_key_;
};

class Insertable_ssk : public Ssk, public Insertable {
public:
    Insertable_ssk(Key_params key, std::string_view docname,
                   const std::vector<std::byte>& priv_key)
        : Ssk{std::move(key), docname}, Insertable(priv_key)
    {}

    Insertable_ssk(Ssk ssk, const std::vector<std::byte>& priv_key)
        : Ssk{std::move(ssk)}, Insertable{priv_key}
    {}

    explicit Insertable_ssk(Token t): Ssk{t}, Insertable{t} {}
    Insertable_ssk() = delete;
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

    explicit Usk(Token t): Subspace_key{t} {}
    Usk() = delete;
    Usk(const Usk& other) = default;
    Usk(Usk&& other) noexcept = default;
    Usk& operator=(const Usk& other) = default;
    Usk& operator=(Usk&& other) noexcept = default;
    ~Usk() override = default;

    [[nodiscard]] Uri to_uri() const override;

    [[nodiscard]] Ssk to_ssk() const;
protected:
    void init_from_uri(const Uri& uri) override;
private:
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
    Insertable_usk(Usk usk, const std::vector<std::byte>& priv_key)
        : Usk(std::move(usk)), Insertable(priv_key)
    {}

    explicit Insertable_usk(Token t): Usk{t}, Insertable{t} {}
    Insertable_usk() = delete;

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

class Ksk : public Insertable_ssk {
public:
    explicit Ksk(std::string keyword);

    explicit Ksk(Token t): Insertable_ssk{t} {}
    Ksk() = delete;

    [[nodiscard]] Uri to_uri() const override;
protected:
    void init_from_uri(const Uri& uri) override;
private:
    std::string keyword_;
};

class Chk : public Key, public Client {
public:
    Chk(Key_params key, bool control_document,
        support::compressor::Compressor_type compressor)
        : Key(std::move(key)), control_document_(control_document),
          compressor_(compressor)
    {}

    explicit Chk(Token t): Key{t} {}
    Chk() = delete;

    [[nodiscard]] Uri to_uri() const override;
    [[nodiscard]] node::Node_key get_node_key() const override;

    static const size_t extra_length = 5;
    static const short routing_key_length = 32;
protected:
    void init_from_uri(const Uri& uri) override;
private:
    void parse_algo(std::byte algo_byte);
    void parse_compressor(std::byte byte_1, std::byte byte_2);
    [[nodiscard]] std::vector<std::byte> get_extra_bytes() const;

    bool control_document_{false};
    support::compressor::Compressor_type compressor_{
        support::compressor::Compressor_type::gzip};
};

} // namespace keys::user

#endif /* LIBHYPHANET_KEYS_USER_H */
