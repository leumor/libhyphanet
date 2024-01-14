#ifndef LIBHYPHANET_KEYS_H
#define LIBHYPHANET_KEYS_H

#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cstddef>
#include <gsl/assert>
#include <gsl/gsl>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace keys {

namespace exception {
    class Malformed_uri : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };
} // namespace exception

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
    Uri_type uri_type{Uri_type::usk};
    std::vector<std::byte> routing_key;
    std::vector<std::byte> crypto_key;
    std::vector<std::byte> extra;
    std::vector<std::string> meta_strings;
};

/**
 * @brief Represents a Hyphanet URI
 *
 * @details
 * Hyphanet's URI is defined as:
 *
 * @verbatim
[freenet:]KeyType@[RoutingKey,CryptoKey,ExtraData][/][docname][/metastring]
@endverbatim
 *
 * * `KeyType`: The type of key (e.g. **CHK**, **SSK**). See
[Uri_type](#Uri_type) and [key_type_](#key_type_).
 * * `RoutingKey`: The routing key. See [routing_key_](#routing_key_).
 * * `CryptoKey`: The cryptographic key. See [crypto_key_](#crypto_key_).
 * * `ExtraData`: Optional base64-encoded data associated with the URI.
 * * `docname`: For **SSKs**, it's hashed with PK fingerprint to get
 *              key value; For **KSKs**, it's KSK's keyword. See
 *              [docname_](#docname_).
 * * `metastring`: Metadata to pass to processors that act on the retrieved
 *                 document. See [meta_strings_](#meta_strings_).
 *
 * For **CHK** keys, it is legal to have a `.extension` tail
 * (e.g. `CHK@blahblahblah.html`). The constructor will remove it.
 */
class Uri {
public:
    /**
     * @brief Construct a new Uri object
     *
     * @param url_params
     */
    explicit Uri(Uri_params url_params);

    Uri() = default;

    /**
     * @brief Create a FreenetURI from its string form.
     *
     * @details
     * May or may not have a freenet: prefix.
     *
     * @param uri The string form of the URI.
     * @param no_trim Whether to
     */
    static std::unique_ptr<Uri> create(std::string_view uri,
                                       bool no_trim = false);

    /**
     * @brief Get the key type from the URI
     *
     * @return Uri_type The key type
     */
    [[nodiscard]] Uri_type get_uri_type() const { return uri_type_; }

    /**
     * @brief Get the routing key from the URI
     *
     * @return The routing key
     */
    [[nodiscard]] const std::vector<std::byte>& get_routing_key() const
    {
        return routing_key_;
    }

    /**
     * @brief Get the crypto key from the URI
     *
     * @return The crypto key
     */
    [[nodiscard]] const std::vector<std::byte>& get_crypto_key() const
    {
        return crypto_key_;
    }

    /**
     * @brief Get the extra data from the URI
     *
     * @return The extra data
     */
    [[nodiscard]] const std::vector<std::byte>& get_extra() const
    {
        return extra_;
    }

    /**
     * @brief Get the meta strings from the URI
     *
     * @return std::optional<std::vector<std::string>> The meta strings
     */
    [[nodiscard]] const std::vector<std::string>& get_meta_strings() const
    {
        return meta_strings_;
    }
private:
    static Uri_type parse_uri_type_str(std::string_view str);

    static std::optional<std::tuple<
        std::vector<std::byte>, std::vector<std::byte>, std::vector<std::byte>>>
    parse_routing_crypto_keys(std::string_view keys_str);

    static std::vector<std::string>
    parse_meta_strings(std::string_view uri_path);

    static const char uri_separator = '/';

    /**
     * @brief The three-letter abbreviation of the key.
     */
    Uri_type uri_type_{Uri_type::ksk};

    /**
     * @brief Routing key
     *
     * @details
     * A **routing key** is a part of a Freenet URI that determines how a file
     * is stored and retrieved on the Freenet network. Freenet uses a key-based
     * routing protocol, similar to distributed hash tables, where each node has
     * a fixed location and routes requests based on the distance between the
     * key and the node’s location. The **routing key** is used to find the
     * closest nodes that store the file, but it does not allow decrypting the
     * file’s contents. To access the file, one also needs the encryption key,
     * which is [the other part](#crypto_key_) of the Freenet URI.
     */
    std::vector<std::byte> routing_key_;

    /**
     * @brief Crypto key
     *
     * @details
     * A **crypto key** is the part of the Freenet URI that allows decrypting
     * the file’s contents. It is usually a random string of characters that is
     * generated when the file is inserted into the network. The **crypto key**
     * is not used for [routing](#routing_key_), but only for accessing the
     * file.
     */
    std::vector<std::byte> crypto_key_;

    /**
     * @brief Extra data associated with the URI.
     *
     * @details
     * Only [CHKs](#user::Chk), [SSKs](#user::Ssk) and [USKs](#user::Usk) have
     * extra data. Different key types have different ways of parsing extra
     * data.
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
     * up the next meta-string in the manifest, and so on.
     *
     * docname is contained in meta_strings_.
     */
    std::vector<std::string> meta_strings_;
};

namespace node {
    class Node_key {
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
         * For [CHKs](#user::Chk), the routing key is the [public key
         * hash](#user::Key#pub_key_hash_).
         *
         * For [Subspace Keys](#user::Subspace_key), it's a SHA-256 hash of the
         * [Encrypted Hashed Document
         * Name](#user::Ssk#encrypted_hashed_docname_) and the [public key
         * hash](#user::Key#pub_key_hash_).
         */
        std::vector<std::byte> node_routing_key_;
    };

    class Node_ssk : public Node_key {
    public:
        static const std::byte ssk_version = std::byte{1};
    };
} // namespace node

} // namespace keys

#endif /* LIBHYPHANET_KEYS_H */
