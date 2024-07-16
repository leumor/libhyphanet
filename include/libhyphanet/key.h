#ifndef LIBHYPHANET_KEY_H
#define LIBHYPHANET_KEY_H

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
     * @return std::vector<std::string> The meta strings
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
} // namespace key

#endif /* LIBHYPHANET_KEY_H */
