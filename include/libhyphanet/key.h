#ifndef LIBHYPHANET_KEY_H
#define LIBHYPHANET_KEY_H

#include "libhyphanet/support.h"
#include <array>
#include <cryptopp/dsa.h>
#include <cryptopp/gfpcrypt.h>
#include <cstddef>
#include <cstdint>
#include <gsl/assert>
#include <gsl/gsl>
#include <libhyphanet/libhyphanet_export.h>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace key {

namespace exception {
    /**
     * @brief Exception class for malformed URIs.
     */
    class LIBHYPHANET_EXPORT Malformed_uri : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };
} // namespace exception

/**
 * @brief Enum class for URI types.
 *
 * @details
 * Defines the types of URIs supported by Hyphanet. Each type has specific
 * characteristics and uses. They are three-letter abbreviation of the key
 * (currently **USK**, **SSK**, **KSK**, or **CHK**).
 *
 * **CHKs** don't support or require a docname. **KSKs** and **SSKs** do.
 * Therefore **CHKs** go straight into metastrings.
 *
 * For **KSKs**, the string keyword (docname) takes the RoutingKey position and
 * the remainder of the fields are inapplicable (except metastring). Examples:
 * @verbatim
hypha:KSK@foo/bar
hypha:KSK@test.html
hypha:test.html
@endverbatim
 *
 */
enum class LIBHYPHANET_EXPORT Uri_type : std::uint8_t {
    usk, ///< [Updatable Subspace Key](#user::Usk)
    ssk, ///< [Signed Subspace Key](#user::Ssk)
    ksk, ///< [Keyword Signed Key](#user::Ksk)
    chk, ///< [Content Hash Key](#user::Chk)
};

/**
 * @brief Mapping from Uri_type to string representation.
 */
static const std::map<Uri_type, std::string> uri_type_to_string = {
    {Uri_type::usk, "USK"},
    {Uri_type::ssk, "SSK"},
    {Uri_type::chk, "CHK"},
    {Uri_type::ksk, "KSK"},
};

/**
 * @brief Length of the cryptographic key.
 */
static const size_t crypto_key_length = 32;

/**
 * @brief Enum class for specifying the cryptographic algorithm used.
 */
enum class Crypto_algorithm : std::underlying_type_t<std::byte> {
    // Remmember to also modify valid_crypto_algorithms if you change this
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
static constexpr std::array<std::byte, 2> valid_crypto_algorithms{std::byte{2},
                                                                  std::byte{3}};

/**
 * @brief Struct to hold parameters for constructing a Uri object.
 */
struct LIBHYPHANET_EXPORT Uri_params {
    Uri_type uri_type{Uri_type::usk};
    std::vector<std::byte> routing_key;
    std::optional<std::array<std::byte, crypto_key_length>> crypto_key;
    std::vector<std::byte> extra;
    std::vector<std::string> meta_strings;
};

// Forward declarations
namespace user::impl {
    class Ssk;
    class Insertable_ssk;
    class Usk;
    class Insertable_usk;
    class Ksk;
    class Chk;
} // namespace user::impl

namespace node {
    class Key;
} // namespace node

/**
 * @brief Represents a Hyphanet URI
 *
 * @details
 * Encapsulates all components of a Hyphanet URI, providing methods to parse,
 * create, and manipulate URIs.
 *
 * Hyphanet's URI is defined as:
 *
 * @verbatim
[freenet:]KeyType@[RoutingKey,CryptoKey,ExtraData][/][docname][/metastring]
@endverbatim
 *
 * * `KeyType`: The type of key (e.g. **CHK**, **SSK**). See
 *              [Uri_type](#Uri_type) and [key_type_](#key_type_).
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
class LIBHYPHANET_EXPORT Uri {
    friend class user::impl::Ssk;
    friend class user::impl::Insertable_ssk;
    friend class user::impl::Usk;
    friend class user::impl::Insertable_usk;
    friend class user::impl::Ksk;
    friend class user::impl::Chk;
public:
    /**
     * @brief Construct a new `Uri` object
     *
     * @details
     * Initializes a `Uri` object with the given parameters. Ensures that either
     * all of [routing_key](#Uri_params#routing_key),
     * [crypto_key](#Uri_params#crypto_key), and [extra](#Uri_params#extra) are
     * provided or none of them are.
     *
     * @param url_params A Uri_params struct containing the
     * initial parameters for the URI.
     */
    explicit Uri(Uri_params url_params);

    Uri() = default;

    /**
     * @brief Static method to create a `Uri` object from a string
     * representation.
     *
     * @details
     * Processes and parses a string representation of a URI into a Uri object.
     * It handles trimming, decoding, and parsing of the URI string.
     *
     * The uri string may or may not have a `freenet:`, `web+freenet`,
     * `ext+freenet`, `hypha`, `hyphanet`, `web+hypha`, `web+hyphanet`,
     * `ext+hypha`, `ext+hyphanet` prefix.
     *
     * @param uri The string representation of the URI.
     * @param no_trim A boolean indicating whether to trim the URI string before
     * processing.
     *
     * @return A std::unique_ptr<Uri> pointing to the newly created Uri
     * object.
     */
    static std::unique_ptr<Uri> create(std::string_view uri,
                                       bool no_trim = false);

    /**
     * @brief Converts the Uri object to a string representation.
     *
     * @details
     * Converts the Uri object into a string format, optionally including a
     * prefix and ensuring the output is in pure ASCII.
     *
     * @param prefix A boolean indicating whether to include `hypha:` prefix
     * in the output string.
     * @param pure_ascii A boolean indicating whether to encode the output
     * string in pure ASCII.
     *
     * @return std::string The Hyphanet URI as a string
     */
    [[nodiscard]] std::string to_string(bool prefix = false,
                                        bool pure_ascii = false) const;

    /**
     * @brief Converts the Uri object to a pure ASCII string representation.
     *
     * @details
     * Encodes any non-English characters as well as any dangerous characters to
     * ensure the string is in pure ASCII format. A `hypha:` prefix will be
     * added.
     *
     * @return std::string The Hyphanet URI as an ASCII string.
     */
    [[nodiscard]] std::string to_ascii_string() const;

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
    [[nodiscard]] const std::optional<std::array<std::byte, crypto_key_length>>&
    get_crypto_key() const
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
    /**
     * @brief Parses the URI type from a string.
     *
     * @details
     * Converts a string representation of a URI type to the corresponding
     * Uri_type enum value.
     *
     * @param str The string representation of the URI type.
     *
     * @return Uri_type The corresponding Uri_type enum value.
     *
     * @throw exception::Malformed_uri If the URI type is unknown.
     */
    static Uri_type parse_uri_type_str(std::string_view str);

    /**
     * @brief Parses routing key, crypto key, and extra data from a string.
     *
     * @details
     * Extracts and decodes the routing key, crypto key, and extra data from a
     * string representation, if present.
     *
     * @param keys_str The string containing the encoded keys and data.
     *
     * @return An optional tuple containing the routing key, crypto key, and
     * extra data if present, otherwise std::nullopt.
     *
     * @throw exception::Malformed_uri If the crypto key is invalid.
     */
    static std::optional<
        std::tuple<std::vector<std::byte>,
                   std::optional<std::array<std::byte, crypto_key_length>>,
                   std::vector<std::byte>>>
    parse_routing_crypto_keys(std::string_view keys_str);

    /**
     * @brief Parses meta strings from a URI path.
     *
     * @details
     * Extracts meta strings from a URI path, handling consecutive slashes and
     * decoding the strings. A URI path is the part of Hyphanet URI after crypto
     * key.
     *
     * @param uri_path The URI path containing the meta strings.
     *
     * @return std::vector<std::string> A vector of meta strings extracted from
     * the URI path.
     */
    static std::vector<std::string>
    parse_meta_strings(std::string_view uri_path);

    static const char uri_separator = '/';

    /**
     * @brief Sets the URI type of the `Uri` object.
     *
     * @details
     * It's used by friend classes.
     *
     * @param uri_type The Uri_type value representing the type of the URI.
     */
    void set_uri_type(Uri_type uri_type) { uri_type_ = uri_type; }

    /**
     * @brief Sets the routing key for the `Uri` object.
     *
     * @details
     * It's used by friend classes.
     *
     * @param routing_key The routing key as a vector of std::byte.
     */
    void set_routing_key(const std::vector<std::byte>& routing_key)
    {
        routing_key_ = routing_key;
    }

    /**
     * @brief Sets the extra data for the `Uri` object.
     *
     * @details
     * It's used by friend classes.
     *
     * @param extra The extra data as a vector of std::byte.
     */
    void set_extra(const std::vector<std::byte>& extra) { extra_ = extra; }

    /**
     * @brief Appends additional meta strings to the `Uri` object.
     *
     * @details
     * Adds a list of meta strings to the existing
     * [meta_strings_](#meta_strings_) of the `Uri` object.
     *
     * @param additional_meta_strings The additional meta strings to append.
     */
    void append_meta_strings(
        const std::vector<std::string>& additional_meta_strings);

    /**
     * @brief Appends a single meta string to the `Uri` object.
     *
     * @details
     * Adds a single meta string to the existing [meta_strings_](#meta_strings_)
     * of the Uri object, decoding it if necessary.
     *
     * @param additional_meta_string The additional meta string to append.
     *
     * @throw exception::Malformed_uri If the meta string is invalid.
     */
    void append_meta_string(std::string_view additional_meta_string);

    /**
     * @brief Appends a single meta string to a vector of meta strings.
     *
     * @details
     * Adds a single meta string to a vector of meta strings, decoding it if
     * necessary.
     *
     * @param meta_strings The vector of meta strings to append to.
     * @param additional_meta_string The additional meta string to append.
     *
     * @throw exception::Malformed_uri If the meta string is invalid.
     */
    static void append_meta_string(std::vector<std::string>& meta_strings,
                                   std::string_view additional_meta_string);

    /**
     * @brief The three-letter abbreviation of the key.
     */
    Uri_type uri_type_{Uri_type::ksk};

    /**
     * @brief Routing key
     *
     * @details
     * A **routing key** is a part of a Hyphanet URI that determines how a file
     * is stored and retrieved on the Hyphanet network. Hyphanet uses a
     * key-based routing protocol, similar to distributed hash tables, where
     * each node has a fixed location and routes requests based on the distance
     * between the key and the node’s location. The **routing key** is used to
     * find the closest nodes that store the file, but it does not allow
     * decrypting the file’s contents. To access the file, one also needs the
     * encryption key, which is [the other part](#crypto_key_) of the Hyphanet
     * URI.
     *
     * For [Insertable](#user::Insertable) keys, the routing key is the private
     * key.
     */
    std::vector<std::byte> routing_key_;

    /**
     * @brief Crypto key
     *
     * @details
     * A **crypto key** is the part of the Hyphanet URI that allows decrypting
     * the file’s contents. It is usually a random string of characters that is
     * generated when the file is inserted into the network. The **crypto key**
     * is not used for [routing](#routing_key_), but only for accessing the
     * file.
     */
    std::optional<std::array<std::byte, crypto_key_length>> crypto_key_;

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
     * Meta strings are parsed by different [Key](#user::Key) types. The docname
     * is included.
     */
    std::vector<std::string> meta_strings_;
};

namespace user {

    /**
     * @brief Struct containing parameters for initializing a Key
     * object.
     *
     * @details
     * This struct encapsulates all the necessary parameters required to
     * initialize a Key object, including the routing key, crypto key,
     * cryptographic algorithm, and any associated meta strings. It is
     * used across various Key types to standardize the initialization
     * and configuration process.
     */
    struct Key_params {
        /**
         * @brief The routing key part of the Key object.
         */
        std::vector<std::byte> routing_key;
        /**
         * @brief The cryptographic key for encrypting/decrypting
         * content.
         */
        std::array<std::byte, crypto_key_length> crypto_key{};
        /**
         * @brief The cryptographic algorithm used for
         * encryption/decryption.
         */
        Crypto_algorithm crypto_algorithm{
            Crypto_algorithm::algo_aes_ctr_256_sha_256};
        /**
         * @brief Meta strings associated with the Key object.
         */
        std::vector<std::string> meta_strings;
    };

    class LIBHYPHANET_EXPORT Key {
    public:
        virtual ~Key() = default;

        /**
         * @brief Constructs a Key object from the given URI.
         *
         * @details
         * This static method creates a unique pointer to a Key object based
         * on the type specified in the Uri. It can create different types
         * of keys such as USK, SSK, CHK, and KSK. The method also
         * determines if the key is insertable based on the extra data in
         * the URI.
         *
         * It calls init_from_uri() of the derived class to initialize the
         * key.
         *
         * @param uri The URI from which to create the Key object.
         *
         * @return A unique pointer to the created Key object.
         *
         * @throws exception::Malformed_uri If the URI is invalid or the key
         * type is unknown.
         */
        [[nodiscard]] static std::unique_ptr<Key> create(const Uri& uri);

        /**
         * @brief Generates the URI representation of the Key object.
         *
         * @details
         * This pure virtual function must be implemented by derived classes
         * to return the URI representation of the Key object. The URI
         * includes all necessary information to identify and use the key,
         * such as the routing key, crypto key, and any meta strings or
         * extra data associated with the key.
         *
         * If the Key is an insertable key, the routing key of the URI is
         * the private key.
         *
         * @return Uri The URI representation of the Key object.
         */
        [[nodiscard]] virtual Uri to_uri() const = 0;

        /**
         * @brief Generates a request Uri for the Key object.
         *
         * @details
         * A request URI is a URI that is used to request content from the
         * network. It does not contain the private key.
         *
         * If you want to give people access to content at an URI, you
         * should always publish only the request URI. Never give away the
         * insert URI, this allows anyone to insert under your URI!
         *
         * This pure virtual function must be implemented by derived classes
         * to return a request URI.
         *
         * @return Uri The request URI for the Key object.
         */
        [[nodiscard]] virtual Uri to_request_uri() const = 0;

        /**
         * @brief Returns the routing key of the Key object.
         *
         * @return The routing key as a vector of bytes.
         */
        [[nodiscard]] virtual std::vector<std::byte> get_routing_key() const
            = 0;

        /**
         * @brief Returns the crypto key of the Key object.
         *
         * @return The crypto key as an array of bytes.
         */
        [[nodiscard]] virtual std::array<std::byte, crypto_key_length>
        get_crypto_key() const = 0;

        /**
         * @brief Returns the cryptographic algorithm used by the Key
         * object.
         *
         * @return The crypto algorithm as an enum value.
         */
        [[nodiscard]] virtual Crypto_algorithm get_crypto_algorithm() const = 0;

        /**
         * @brief Returns the meta strings associated with the Key object.
         *
         * @return A constant reference to the vector of meta strings.
         */
        [[nodiscard]] virtual const std::vector<std::string>&
        get_meta_strings() const
            = 0;
    };

    /**
     * @brief **Subspace %Key** is a subtype of Key that encoded a [document
     * name](#doc_name_) (can be used as a site name) into it.
     *
     * @details
     * It's usually for sites that are going to change over time. For
     * example, a website that may need news to be updated or information to
     * be corrected, added or deleted.
     *
     * The [document name](#doc_name_) will later be used to generate a
     * [routing key](#node::Node_key#routing_key_).
     *
     */
    class LIBHYPHANET_EXPORT Subspace_key : public virtual Key {
    public:
        [[nodiscard]] virtual std::string get_docname() const = 0;

        /**
         * @brief The fixed length of the extra data segment in the URI for
         * a Subspace_key object.
         *
         * @details
         * This constant defines the length of the extra data segment that
         * is appended to the URI of a Subspace_key. The extra data segment
         * contains additional information necessary for the Subspace_key,
         * such as the cryptographic algorithm used, control document flag,
         * and compression algorithm. The length is set to 5 bytes to
         * accommodate these details.
         */
        static const size_t extra_length = 5;

        /**
         * @brief The standard length of the routing key used in the URI for
         * a Subspace_key object.
         *
         * @details
         * This constant specifies the length of the routing key part of the
         * URI for a Subspace_key. The routing key is a crucial component
         * used in the network layer to route requests to the appropriate
         * node holding the content. For Subspace Keys, the routing key
         * length is fixed at 32 bytes to ensure consistency and
         * compatibility across the network.
         */
        static const size_t routing_key_size
            = 32; // TODO: same as Node_ssk::pubkey_hash_size
    };

    /**
     * @brief A mixin class for Client Keys.
     *
     * @details
     * Client keys are decodable. Node keys are not. When data has been
     * fetched to a node-level Key Block, it can only be decoded after a
     * Client Key Block has been constructed from the node-level block and
     * the client key. The client key generally contains the encryption keys
     * which the node level does not know about, but which are in the URI -
     * usually the second part, after the comma.
     */
    class LIBHYPHANET_EXPORT Client {
    public:
        virtual ~Client() = default;

        /**
         * @brief Returns the node key corresponding to this key.
         *
         * @return The node key as a `node::Node_key` object.
         */
        [[nodiscard]] virtual std::unique_ptr<key::node::Key>
        get_node_key() const = 0;
    };

    /**
     * @brief A mixin class for Insertable Keys.
     *
     * @details
     * A Insertable key contains a private key from the [Key](#Key) owner,
     * so a user can use it to insert new versions of data.
     */
    class LIBHYPHANET_EXPORT Insertable {
    public:
        virtual ~Insertable() = default;

        [[nodiscard]] virtual std::vector<std::byte> get_priv_key() const = 0;
    };

    class Usk;

    /**
     * @brief Represents a **Signed Subspace %Key** (SSK) in the Hyphanet
     * network.
     *
     * @details
     * SSKs are used for mutable content where updates are expected. They
     * include a public key for verification of content updates. SSKs are a
     * fundamental part of Hyphanet's data storage and retrieval system,
     * allowing for secure, anonymous, and verifiable updates to content.
     */
    class LIBHYPHANET_EXPORT Ssk : public virtual Subspace_key, public Client {
    public:
        /**
         * @brief Converts an Ssk (Signed Subspace Key) to a Usk (Updatable
         * Subspace Key) if possible.
         *
         * @details
         * This method attempts to convert the current Ssk object into a Usk
         * object. The conversion is based on parsing the document name of
         * the Ssk to extract a site name and an edition number. If the
         * document name follows the expected format that includes an
         * edition number, a Usk object is created with the same routing
         * key, crypto key, cryptographic algorithm, and meta strings as the
         * Ssk, but with the addition of the extracted site name and edition
         * number.
         *
         * The method is useful for scenarios where mutable content is
         * accessed through Ssk but needs to be managed or referenced as Usk
         * for updates or versioning purposes.
         *
         * @return A std::optional containing a Usk object if the conversion
         * is successful, or an empty optional if the document name does not
         * include an edition number or does not follow the expected format.
         */
        [[nodiscard]] virtual std::optional<std::unique_ptr<key::user::Usk>>
        to_usk() const = 0;

        [[nodiscard]] virtual std::optional<std::vector<std::byte>>
        get_pub_key() const = 0;

        /**
         * @brief The character to separate the site name from the edition
         * number in its SSK form.
         *
         * @details
         * The reason for choosing '-' is that it makes it ludicrously easy
         * to go from the **USK** form to the **SSK** form, and we don't
         * need to go vice versa.
         */
        static constexpr auto separator = '-';
    };

    /**
     * @brief An insertable version of an Ssk, containing a private key for
     * data insertion.
     *
     * @details
     * Insertable SSKs allow users to insert new versions of data into the
     * Hyphanet network. They are crucial for maintaining mutable content
     * where the owner wishes to update the content securely.
     */
    class LIBHYPHANET_EXPORT Insertable_ssk : public virtual Ssk,
                                              public virtual Insertable {};

    /**
     * @brief Represents an **Updatable Subspace %Key** (USK) for dynamic
     * content updates.
     *
     * @details
     * USKs facilitate a crude updating mechanism at the client level,
     * allowing users to request the latest version of a file without
     * knowing the exact SSK. This is particularly useful for dynamic
     * content such as blogs or forums.
     *
     * Example:
     *
     * ```
     * freenet:USK@~Alice/MyBlog/2024-01-02.html/5
     * ```
     *
     * It isn't really a **Client %Key** as it cannot be directly
     * requested.
     *
     * It contains:
     * - Enough information to produce a real SSK.
     * - [Document name](#Subspace_key#docname_).
     * - [Document edition number](#suggested_edition_).
     */
    class LIBHYPHANET_EXPORT Usk : public virtual Subspace_key {
    public:
        [[nodiscard]] virtual long get_suggested_edition() const = 0;

        /**
         * @brief Converts a Usk (Updatable Subspace Key) to an Ssk (Signed
         * Subspace Key).
         *
         * @details
         * This method converts the current Usk object into an Ssk object.
         * The conversion involves creating a new Ssk object with the same
         * routing key, cryptographic key, cryptographic algorithm, and meta
         * strings as the Usk, but with the document name and edition number
         * formatted according to the Ssk's requirements.
         *
         * The Ssk created by this method represents a specific edition of
         * the content identified by the Usk, allowing for direct access to
         * that edition. This is particularly useful for retrieving or
         * referencing a specific version of mutable content within the
         * network.
         *
         * @return An Ssk object representing a specific edition of the
         * content identified by the current Usk.
         */
        [[nodiscard]] virtual std::unique_ptr<Ssk> to_ssk() const = 0;
    };

    /**
     * @brief An insertable version of a Usk, containing a private key for
     * data insertion.
     *
     * @details
     * Similar to Insertable SSKs, Insertable USKs allow for the insertion
     * of new data versions but with the added functionality of USKs for
     * dynamic content updates.
     */
    class LIBHYPHANET_EXPORT Insertable_usk : public virtual Usk,
                                              public virtual Insertable {};

    /**
     * @brief Represents a **Keyword Signed %Key** (KSK) in the Hyphanet
     * network.
     *
     * @details
     * KSKs are a simple form of keys that are derived directly from a
     * human-readable string. They are less secure than SSKs or USKs but
     * offer a straightforward way to share and access static content.
     */
    class LIBHYPHANET_EXPORT Ksk : public virtual Insertable_ssk {};

    /**
     * @brief Represents a **Content Hash %Key** (CHK) in the Hyphanet
     * network.
     *
     * @details
     * CHks are used for immutable content. The key is derived from the
     * content itself, ensuring that any request for a CHK retrieves the
     * exact content that was originally inserted. CHks are fundamental to
     * Hyphanet's goal of censorship-resistant storage.
     */
    class LIBHYPHANET_EXPORT Chk : public virtual Key, public virtual Client {
    public:
        [[nodiscard]] virtual bool get_control_document() const = 0;
        [[nodiscard]] virtual support::compressor::Compressor_type
        get_compressor() const
            = 0;

        /**
         * @brief The fixed length of the extra data segment in the URI for
         * a Chk object.
         *
         * @details
         * This constant defines the length of the extra data segment that
         * is appended to the URI of a Content Hash Key (CHK). The extra
         * data segment contains additional information necessary for the
         * CHK, such as the cryptographic algorithm used, control document
         * flag, and compression algorithm. The length is set to 5 bytes to
         * accommodate these details.
         */
        static const size_t extra_length = 5;

        /**
         * @brief The standard length of the routing key used in the URI for
         * a Chk object.
         *
         * @details
         * This constant specifies the length of the routing key part of the
         * URI for a Content Hash Key (CHK). The routing key is a crucial
         * component used in the network layer to route requests to the
         * appropriate node holding the content. For CHks, the routing key
         * length is fixed at 32 bytes to ensure consistency and
         * compatibility across the network.
         */
        static const short routing_key_length = 32;
    };
} // namespace user
namespace node {

    /**
     * @brief Base class for node keys.
     */
    class LIBHYPHANET_EXPORT Key {
    public:
        virtual ~Key() = default;

        /**
         * @brief Get the full key.
         *
         * @details
         * Including any crypto type bytes, everything needed to construct a Key
         * object.
         *
         * @return std::vector<std::byte> the full key bytes.
         */
        [[nodiscard]] virtual std::vector<std::byte> get_full_key() const = 0;

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
        [[nodiscard]] virtual std::unique_ptr<Key> archival_copy() const = 0;

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
        [[nodiscard]] virtual short get_type() const = 0;

        /**
         * @brief Get the key bytes.
         *
         * @details
         * Not just the routing key, enough data to reconstruct the key
         * (excluding any pubkey needed).
         *
         * @return std::vector<std::byte> the key bytes.
         */
        [[nodiscard]] virtual std::vector<std::byte> get_key_bytes() const = 0;

        [[nodiscard]] virtual double to_normalized_double() = 0;

        [[nodiscard]] virtual const std::vector<std::byte>&
        get_node_routing_key() const
            = 0;
        [[nodiscard]] virtual Crypto_algorithm get_crypto_algorithm() const = 0;
    };

    class LIBHYPHANET_EXPORT Chk : public virtual Key {
    public:
        static const std::byte base_type = std::byte{1};
        static const size_t key_length = 32;
        static const size_t full_key_length = 34;
    };

    class LIBHYPHANET_EXPORT Ssk : public virtual Key {
    public:
        [[nodiscard]] virtual std::array<std::byte, 32>
        get_encrypted_hashed_docname() const = 0;

        [[nodiscard]] virtual std::optional<std::vector<std::byte>>
        get_pub_key() const = 0;

        static const std::byte ssk_version = std::byte{1};
        static const std::byte base_type = std::byte{2};
        static const size_t full_key_length = 66;
    };

    class LIBHYPHANET_EXPORT Archive_ssk : public virtual Ssk {};
} // namespace node
} // namespace key

#endif /* LIBHYPHANET_KEY_H */
