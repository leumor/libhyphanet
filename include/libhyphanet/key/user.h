#ifndef LIBHYPHANET_KEY_USER_H
#define LIBHYPHANET_KEY_USER_H

#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
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

namespace key::user {

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
    [[nodiscard]] virtual std::vector<std::byte> get_routing_key() const = 0;

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
    [[nodiscard]] virtual std::unique_ptr<node::Key> get_node_key() const = 0;
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

} // namespace key::user

#endif /* LIBHYPHANET_KEY_USER_H */
