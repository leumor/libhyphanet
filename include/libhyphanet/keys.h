#ifndef CB0C4773_63F9_4A85_8F51_20734B26AA79
#define CB0C4773_63F9_4A85_8F51_20734B26AA79

#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cstddef>
#include <gsl/assert>
#include <gsl/gsl>
#include <string>
#include <string_view>
#include <vector>

namespace keys {

/**
 * @brief Three-letter abbreviation of the key (currently **USK**, **SSK**,
* **KSK**, or **CHK**).
 *
 * @details
 * **CHKs** don't support or require a docname. **KSKs** and **SSKs** do.
 * Therefore **CHKs** go straight into metastrings.
 *
 * For **KSKs**, the string keyword (docname) takes the RoutingKey position and
 * the remainder of the fields are inapplicable (except metastring). Examples:
 * @verbatim
freenet:KSK@foo/bar
freenet:KSK@test.html
freenet:test.html
@endverbatim
 *
 */
enum class Uri_type {
    usk, ///< [Updatable Subspace Key](#user::Usk)
    ssk, ///< [Signed Subspace Key](#user::Ssk)
    ksk, ///< [Keyword Signed Key](#user::Ksk)
    chk, ///< [Content Hash Key](#user::Chk)
};

struct Uri_params {
    Uri_type key_type;
    std::string_view docname;
    std::vector<std::string> meta_strings;
    std::vector<std::byte> routing_key;
    std::vector<std::byte> crypto_key;
    std::vector<std::byte> extra;
    long suggested_edition{-1};
};

/**
 * @brief Represents a Hyphanet URI
 *
 * @details
 * Hyphanet's URI is defined as:
 *
 * @verbatim
freenet:[KeyType@]RoutingKey,CryptoKey[,ExtraData][/docname][/suggestedEdition][/metastring]
@endverbatim
 *
 * * `KeyType`: The type of key (e.g. **CHK**, **SSK**). See
[Uri_type](#Uri_type) and [key_type_](#key_type_).
 * * `RoutingKey`: The routing key. See [routing_key_](#routing_key_).
 * * `CryptoKey`: The cryptographic key. See [crypto_key_](#crypto_key_).
 * * `ExtraData`: Optional base64-encoded data associated with the URI.
 * * `docname`: Only meaningful for **SSKs**. Hashed with PK fingerprint to get
 *              key value. See [docname_](#docname_).
 * * `suggestedEdition`: Only meaningful for **USKs**. See
[Usk](#user::Usk).
 * * `metastring`: Metadata to pass to processors that act on the retrieved
 *                 document. See [meta_strings_](#meta_strings_).
 *
 * For **CHK** keys, it is legal to have a `.extension` tail
 * (e.g. `CHK@blahblahblah.html`). The constructor will remove it.
 */
class Uri {
public:
    /**
     * @brief Create a FreenetURI from its string form.
     *
     * @details
     * May or may not have a freenet: prefix.
     *
     * @param uri The string form of the URI.
     * @param no_trim Whether to
     */
    Uri(std::string_view uri, bool no_trim = false);

    /**
     * @brief Construct a new Uri object
     *
     * @param url_params
     */
    explicit Uri(const Uri_params& url_params);

    /**
     * @brief Get the docname from the URI
     *
     * @return std::string The docname
     */
    [[nodiscard]] std::string get_docname() const { return docname_; }
private:
    /**
     * @brief The three-letter abbreviation of the key.
     */
    Uri_type key_type_{Uri_type::ksk};

    /**
     * @brief The modified Base64 encoded key value.
     */
    std::vector<std::byte> routing_key_;

    /**
     * @brief The modified Base64 encoded decryption key.
     */
    std::vector<std::byte> crypto_key_;

    /**
     * @brief Extra data associated with the URI.
     */
    std::vector<std::byte> extra_;

    /**
     * @brief The meta-strings, in the order they are given.
     *
     * @details
     * Typically we will construct the base key from the key type, routing key,
     * extra, and document name (`SSK@blah,blah,blah/filename`,
     * `CHK@blah,blah,blah`, `KSK@filename` or
     * `USK@blah,blah,blah/filename/20`), fetch it, discover that it is a
     * manifest, and look up the first meta-string. If this is the final data,
     * we use that (and complain if there are meta-strings left), else we look
     * up the next meta-string in the manifest, and so on. */
    std::vector<std::string> meta_strings_;

    /**
     * @brief Only meaningful for **SSKs**, and is hashed with the
     * PK fingerprint to get the key value.
     */
    std::string docname_;

    /**
     * @brief for **USKs** only. See [Usk](#user::Usk).
     */
    long suggested_edition_{-1};
};

namespace node {
    class Node_key {
    private:
        /**
         * @brief Routing key.
         *
         * @details
         * The **routing key** is based on the hash of the data or the public
         * key of the owner, and it determines how close a node is to the data.
         * Nodes use the routing key to forward requests to the node that is
         * most responsible for storing the data, or the closest one they know
         * of.
         *
         * For [CHKs](#user::Chk), the routing key is the [public key
         * hash](#user::Key#pub_key_hash_).
         *
         * For [Subspace Keys](#user::Subspace_key), it's a SHA-256 hash of the
         * [Encrypted Hashed Document
         * Name](#user::Ssk#encrypted_hashed_docname_) and the [public key
         * hash](#user::Key#pub_key_hash_).
         */
        std::vector<std::byte> routing_key_;
    };
} // namespace node

namespace user {
    /**
     * @brief Interface for user keys that can be converted to a [URI](#Uri).
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
        Key(std::vector<std::byte> pub_key_hash,
            std::vector<std::byte> crypto_key,
            Crypto_algorithm crypto_algorithm)
            : pub_key_hash_(std::move(pub_key_hash)),
              crypto_key_(std::move(crypto_key)),
              crypto_algorithm_(crypto_algorithm)
        {}
        virtual ~Key() = default;

        [[nodiscard]] virtual std::string to_uri() const = 0;
    protected:
        [[nodiscard]] std::vector<std::byte> get_routing_key() const
        {
            return pub_key_hash_;
        }
        [[nodiscard]] std::vector<std::byte> get_crypto_key() const
        {
            return crypto_key_;
        }
    private:
        /**
         * @brief Public key hash.
         *
         * @details
         * Public key hash is a part of the Freenet URI (address) that
         * is used to generate a [routing key](#node::Node_key#routing_key_)
         * which can later be used to locate and request data blocks on the
         * network.
         *
         * The hash itself is calculated differently depending on the key type.
         */
        std::vector<std::byte> pub_key_hash_;

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
        Crypto_algorithm crypto_algorithm_;
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
        Subspace_key(std::string_view docname,
                     std::vector<std::byte> pub_key_hash,
                     std::vector<std::byte> crypto_key,
                     Crypto_algorithm crypto_algorithm)
            : Key{std::move(pub_key_hash), std::move(crypto_key),
                  crypto_algorithm},
              doc_name_(docname)
        {}

        ~Subspace_key() override = 0;
        [[nodiscard]] std::string get_docname() const { return doc_name_; }
    private:
        /**
         * @brief Document name.
         *
         * @details
         * A docname (sometimes called site name) is a part of the address that
         * provides a human-readable name for the file. It will later be used to
         * generate a [routing key](#node::Node_key#routing_key_).
         *
         * @sa
         * - [Ssk#encrypted_hashed_docname_](#Ssk#encrypted_hashed_docname_)
         * - [Key#pub_key_hash_](#Key#pub_key_hash_)
         * - [Key#crypto_key_](#Key#crypto_key_)
         */
        std::string doc_name_;
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
    private:
        /**
         * @brief The character to separate the site name from the edition
         * number in its SSK form.
         *
         * @details
         * The reason for choosing '-' is that it makes it ludicrously easy to
         * go from the **USK** form to the **SSK** form, and we don't need to go
         * vice versa.
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

    class Insertable_usk : public Insertable, public Usk {};

    class Chk : public Key, public Client {};
    class Ssk : public Subspace_key, public Client {
    private:
        std::vector<std::byte> encrypted_hashed_docname_;
    };
    class Insertable_ssk : public Insertable, public Ssk {};

    class Ksk : public Insertable_ssk {};

} // namespace user

} // namespace keys

#endif /* CB0C4773_63F9_4A85_8F51_20734B26AA79 */
