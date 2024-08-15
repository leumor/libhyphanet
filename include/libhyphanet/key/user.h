#ifndef LIBHYPHANET_KEY_USER_H
#define LIBHYPHANET_KEY_USER_H

#include "libhyphanet/key.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/support.h"

#include <algorithm>
#include <array>
#include <concepts>
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
#include <typeindex>
#include <utility>
#include <vector>

namespace key::user {

namespace concepts {
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
    template<typename T>
    concept Has_To_Uri = requires(T t) {
        { t.to_uri() } -> std::same_as<Uri>;
    };

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
    template<typename T>
    concept Has_To_Request_Uri = requires(T t) {
        { t.to_request_uri() } -> std::same_as<Uri>;
    };

    /**
     * @brief Returns the routing key of the Key object.
     *
     * @return The routing key as a vector of bytes.
     */
    template<typename T>
    concept Has_Get_Routing_Key = requires(const T t) {
        { t.get_routing_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Returns the crypto key of the Key object.
     *
     * @return The crypto key as an array of bytes.
     */
    template<typename T>
    concept Has_Get_Crypto_Key = requires(const T t) {
        {
            t.get_crypto_key()
        } -> std::same_as<std::array<std::byte, crypto_key_length>>;
    };

    /**
     * @brief Returns the cryptographic algorithm used by the Key
     * object.
     *
     * @return The crypto algorithm as an enum value.
     */
    template<typename T>
    concept Has_Get_Crypto_Algorithm = requires(const T t) {
        { t.get_crypto_algorithm() } -> std::same_as<Crypto_algorithm>;
    };

    /**
     * @brief Returns the meta strings associated with the Key object.
     *
     * @return A constant reference to the vector of meta strings.
     */
    template<typename T>
    concept Has_Get_Meta_Strings = requires(const T t) {
        {
            t.get_meta_strings()
        } -> std::same_as<const std::vector<std::string>&>;
    };

    template<typename T>
    concept Key = Has_To_Uri<T> && Has_To_Request_Uri<T>
               && Has_Get_Routing_Key<T> && Has_Get_Crypto_Key<T>
               && Has_Get_Crypto_Algorithm<T> && Has_Get_Meta_Strings<T>;

    template<typename T>
    concept Has_Get_Docname = requires(const T t) {
        { t.get_docname() } -> std::same_as<std::string>;
    };

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
    template<typename T>
    concept Has_Extra_Length = requires {
        { T::extra_length } -> std::convertible_to<size_t>;
    };

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
    template<typename T>
    concept Has_Routing_Key_Size = requires {
        { T::routing_key_size } -> std::convertible_to<size_t>;
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
    template<typename T>
    concept Subspace_Key = Key<T> && Has_Get_Docname<T> && Has_Extra_Length<T>
                        && Has_Routing_Key_Size<T>;

    /**
     * @brief Returns the node key corresponding to this key.
     *
     * @return The node key as a `node::Node_key` object.
     */
    template<typename T>
    concept Has_Get_Node_Key = requires(const T t) {
        { t.get_node_key() } -> std::same_as<std::unique_ptr<key::node::Key>>;
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
    template<typename T>
    concept Client = Has_Get_Node_Key<T>;

    template<typename T>
    concept Has_Get_Priv_Key = requires(const T t) {
        { t.get_priv_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief A mixin class for Insertable Keys.
     *
     * @details
     * A Insertable key contains a private key from the [Key](#Key) owner,
     * so a user can use it to insert new versions of data.
     */
    template<typename T>
    concept Insertable = Has_Get_Priv_Key<T>;

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
     * @return A Usk object if the conversion is successful, or a nullptr if the
     * document name does not include an edition number or does not follow the
     * expected format.
     */
    template<typename T, typename U>
    concept Has_To_Usk = requires(const T t) {
        { t.to_usk() } -> std::same_as<std::unique_ptr<U>>;
    };

    template<typename T>
    concept Has_Get_Pub_Key = requires(const T t) {
        { t.get_pub_key() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief The character to separate the site name from the edition
     * number in its SSK form.
     *
     * @details
     * The reason for choosing '-' is that it makes it ludicrously easy
     * to go from the **USK** form to the **SSK** form, and we don't
     * need to go vice versa.
     */
    template<typename T>
    concept Has_Separator = requires {
        { T::separator } -> std::convertible_to<char>;
    };

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
    template<typename T, typename U>
    concept Ssk = Subspace_Key<T> && Client<T> && Has_To_Usk<T, U>
               && Has_Get_Pub_Key<T> && Has_Separator<T>;

    /**
     * @brief An insertable version of an Ssk, containing a private key for
     * data insertion.
     *
     * @details
     * Insertable SSKs allow users to insert new versions of data into the
     * Hyphanet network. They are crucial for maintaining mutable content
     * where the owner wishes to update the content securely.
     */
    template<typename T, typename U>
    concept Insertable_Ssk = Ssk<T, U> && Insertable<T>;

    template<typename T>
    concept Has_Get_Suggested_Edition = requires(const T t) {
        { t.get_suggested_edition() } -> std::same_as<long>;
    };

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
    template<typename T, typename U>
    concept Has_To_Ssk = requires(const T t) {
        { t.to_ssk() } -> std::same_as<std::unique_ptr<U>>;
    };

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
    template<typename T, typename U>
    concept Usk =
        Subspace_Key<T> && Has_Get_Suggested_Edition<T> && Has_To_Ssk<T, U>;

    /**
     * @brief An insertable version of a Usk, containing a private key for
     * data insertion.
     *
     * @details
     * Similar to Insertable SSKs, Insertable USKs allow for the insertion
     * of new data versions but with the added functionality of USKs for
     * dynamic content updates.
     */
    template<typename T, typename U>
    concept Insertable_Usk = Usk<T, U> && Insertable<T>;

    /**
     * @brief Represents a **Keyword Signed %Key** (KSK) in the Hyphanet
     * network.
     *
     * @details
     * KSKs are a simple form of keys that are derived directly from a
     * human-readable string. They are less secure than SSKs or USKs but
     * offer a straightforward way to share and access static content.
     */
    template<typename T, typename U>
    concept Ksk = Insertable_Ssk<T, U>;

    template<typename T>
    concept Has_Get_Control_Document = requires(const T t) {
        { t.get_control_document() } -> std::same_as<bool>;
    };

    template<typename T>
    concept Has_Get_Compressor = requires(const T t) {
        {
            t.get_compressor()
        } -> std::same_as<support::compressor::Compressor_type>;
    };

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
    template<typename T>
    concept Chk = Key<T> && Client<T> && Has_Get_Control_Document<T>
               && Has_Get_Compressor<T> && Has_Extra_Length<T>
               && Has_Routing_Key_Size<T>;
} // namespace concepts

class LIBHYPHANET_EXPORT Any_key {
public:
    template<concepts::Key T>
    requires(!std::same_as<Any_key, std::remove_cvref_t<T>>)
    explicit(false) Any_key(std::shared_ptr<T> key)
        : ptr_{std::make_shared<Model<T>>(key)}
    {}

    [[nodiscard]] std::vector<std::byte> get_routing_key() const
    {
        return ptr_->get_routing_key();
    }

    [[nodiscard]] std::array<std::byte, crypto_key_length>
    get_crypto_key() const
    {
        return ptr_->get_crypto_key();
    }

    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const
    {
        return ptr_->get_crypto_algorithm();
    }

    [[nodiscard]] const std::vector<std::string>& get_meta_strings() const
    {
        return ptr_->get_meta_strings();
    }

    [[nodiscard]] Uri to_uri() const { return ptr_->to_uri(); }

    [[nodiscard]] Uri to_request_uri() const { return ptr_->to_request_uri(); }

    template<typename T>
    [[nodiscard]] bool is() const
    {
        return ptr_->type_id() == typeid(T);
    }

    template<typename T>
    [[nodiscard]] std::shared_ptr<std::decay_t<T>> as()
    {
        if (is<T>()) {
            return std::static_pointer_cast<Model<T>>(ptr_)->get_value();
        }
        return nullptr;
    }

private:
    struct Concept {
        virtual ~Concept() = default;
        [[nodiscard]] virtual std::vector<std::byte>
        get_routing_key() const = 0;
        [[nodiscard]] virtual std::array<std::byte, crypto_key_length>
        get_crypto_key() const = 0;
        [[nodiscard]] virtual Crypto_algorithm get_crypto_algorithm() const = 0;
        [[nodiscard]] virtual const std::vector<std::string>&
        get_meta_strings() const = 0;
        [[nodiscard]] virtual Uri to_uri() const = 0;
        [[nodiscard]] virtual Uri to_request_uri() const = 0;

        [[nodiscard]] virtual std::type_index type_id() const = 0;
    };

    template<concepts::Key T>
    struct Model : Concept {
        explicit(false) Model(std::shared_ptr<T> v)
            : value_{std::move(v)}
        {}

        [[nodiscard]] std::vector<std::byte> get_routing_key() const override
        {
            return value_->get_routing_key();
        }

        [[nodiscard]] std::array<std::byte, crypto_key_length>
        get_crypto_key() const override
        {
            return value_->get_crypto_key();
        }

        [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const override
        {
            return value_->get_crypto_algorithm();
        }

        [[nodiscard]] const std::vector<std::string>&
        get_meta_strings() const override
        {
            return value_->get_meta_strings();
        }

        [[nodiscard]] Uri to_uri() const override { return value_->to_uri(); }

        [[nodiscard]] Uri to_request_uri() const override
        {
            return value_->to_request_uri();
        }

        [[nodiscard]] std::type_index type_id() const override
        {
            return typeid(T);
        }

        [[nodiscard]] std::shared_ptr<std::decay_t<T>> get_value() const
        {
            return value_;
        }

    private:
        std::shared_ptr<std::decay_t<T>> value_;
    };

    std::shared_ptr<Concept> ptr_;
};

static_assert(concepts::Key<Any_key>);

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
struct LIBHYPHANET_EXPORT Key_params {
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
    Crypto_algorithm crypto_algorithm{Crypto_algorithm::algo_aes_ctr_256_sha_256
    };
    /**
     * @brief Meta strings associated with the Key object.
     */
    std::vector<std::string> meta_strings;
};

class Insertable;

/**
 * @brief Abstract base class for user keys that can be converted to a
 * Uri.
 *
 * @details
 * Key is the base class for various types of user keys in the system.
 * It provides the common interface and functionalities for all derived
 * key types. The derived classes represent different key types and
 * handle their specific behaviors and properties.
 *
 * There are currently two categories of user keys:
 *
 * - **%Client %Key**: Client keys are decodable. The client key
 * generally contains the encryption keys which the node level does not
 *               know about, but which are in the URI - usually the
 * second part, after the comma.
 * - **Non %Client %Key**: Things like Usk, which don't directly
 * translate to a routing key. But it usually can be converted to a
 * Client %Key by some algorithm.
 */
class LIBHYPHANET_EXPORT Key {
protected:
    /**
     * @brief A protected token to prevent constructors from being
     * publicly called.
     *
     * @sa
     * [C.50](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#c50-use-a-factory-function-if-you-need-virtual-behavior-during-initialization)
     */
    class Token {};
    friend class Insertable;

    template<concepts::Key T, concepts::Key Key_type>
    friend std::shared_ptr<T> create_and_init_key(const Uri& uri);

    friend void init_from_url(Key& key, const Uri& uri);

public:
    /**
     * @brief Constructs a Key object with specified parameters.
     *
     * @details
     * This constructor initializes a Key object with the provided key
     * parameters, which include the routing key, cryptographic key,
     * cryptographic algorithm, and any associated meta strings. It is
     * used to create a Key object with specific cryptographic
     * properties and associated data.
     *
     * @param key A Key_params structure containing the initial
     * parameters for the Key object.
     *
     * @throws exception::Malformed_uri If any of the provided key
     * parameters are invalid, this constructor will invoke
     * check_invariants() which may throw an exception.
     */
    explicit Key(Key_params key)
        : routing_key_(std::move(key.routing_key)),
          crypto_key_(key.crypto_key),
          crypto_algorithm_(key.crypto_algorithm),
          meta_strings_(key.meta_strings)
    {
        check_invariants();
    }

    explicit Key(Token /*unused*/) {}

    Key() = delete;
    virtual ~Key() = default;

    /**
     * @brief Returns the routing key of the Key object.
     *
     * @return The routing key as a vector of bytes.
     */
    [[nodiscard]] std::vector<std::byte> get_routing_key() const
    {
        return routing_key_;
    }

    /**
     * @brief Returns the crypto key of the Key object.
     *
     * @return The crypto key as an array of bytes.
     */
    [[nodiscard]] std::array<std::byte, crypto_key_length>
    get_crypto_key() const
    {
        return crypto_key_;
    }

    /**
     * @brief Returns the cryptographic algorithm used by the Key
     * object.
     *
     * @return The crypto algorithm as an enum value.
     */
    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const
    {
        return crypto_algorithm_;
    }

    /**
     * @brief Returns the meta strings associated with the Key object.
     *
     * @return A constant reference to the vector of meta strings.
     */
    [[nodiscard]] const std::vector<std::string>& get_meta_strings() const
    {
        return meta_strings_;
    }

protected:
    /**
     * @brief Initializes a Key object from a Uri.
     *
     * @details
     * This method initializes the Key object using the routing key,
     * crypto key, and meta strings extracted from the given Uri. It
     * checks the validity of the URI and throws an exception if the URI
     * is malformed.
     *
     * @param uri The Uri from which to initialize the Key object.
     *
     * @throws exception::Malformed_uri If the URI is invalid or the
     * crypto key is invalid.
     *
     * @sa Key::create()
     */
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

    /**
     * @brief Pops and returns the first meta string from the Key
     * object.
     *
     * @details
     * This method removes the first meta string from the Key object's
     * meta strings and returns it. If there are no meta strings left,
     * it returns std::nullopt.
     *
     * @return A non-empty string containing the first meta string if
     * available, or an empty string if there are no meta strings left.
     */
    std::string pop_meta_strings();

private:
    /**
     * @brief Checks the invariants of the Key object.
     *
     * @details
     * This method checks the internal state of the Key object to ensure
     * that all required fields such as the routing key are properly
     * set. It throws an exception if any invariant is violated.
     *
     * @throws exception::Malformed_uri If the routing key is missing or
     * invalid.
     */
    void check_invariants() const;

    /**
     * @brief Client Routing key.
     *
     * @details
     * Client Routing key is a part of the Hyphanet URI (address) that
     * is used to generate a [Node Routing
     * Key](#node::Node_key#node_routing_key_) which can later be used
     * to locate and request data blocks on the network.
     *
     * The hash itself is calculated differently depending on the key
     * type.
     */
    std::vector<std::byte> routing_key_;

    /**
     * @brief The encryption key.
     *
     * @details
     * A encryption key is a part of the Hyphanet URI (address) that is
     * used to decrypt the data once it is downloaded.The encryption key
     * is usually randomly generated and not related to the routing key.
     * The node that stores the data only knows the routing key, and
     * cannot decrypt the data without the encryption key.
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
        Crypto_algorithm::algo_aes_pcfb_256_sha_256
    };

    std::vector<std::string> meta_strings_;
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
    /**
     * @brief Constructs an Insertable object with a specified private
     * key.
     *
     * @details
     * This constructor initializes an Insertable object with a private
     * key provided by the user. The private key is used to insert new
     * versions of data into the network. It is essential for
     * maintaining mutable content where the owner wishes to update the
     * content securely.
     *
     * @param priv_key The private key as a vector of bytes, which will
     * be used for data insertion.
     */
    explicit Insertable(const std::vector<std::byte>& priv_key)
        : priv_key_{priv_key}
    {}

    explicit Insertable(Key::Token /*unused*/) {}

    Insertable() = delete;
    virtual ~Insertable() = default;

    /**
     * @brief Return the private key for the current Key.
     *
     * @return The private key as a vector of bytes.
     */
    [[nodiscard]] std::vector<std::byte> get_priv_key() const
    {
        return priv_key_;
    }

protected:
    /**
     * @brief Set the private key for the current Key.
     *
     * @param key The private key as a vector of bytes.
     */
    void set_priv_key(std::vector<std::byte> key)
    {
        priv_key_ = std::move(key);
    }

private:
    /**
     * @brief Private key for current Key.
     *
     * @details
     * The private key bytes are big-endian encoded `x` values.
     *
     * It can be used to encrypt and sign the data for current Key.
     * Once signed, the data can be inserted into the network.
     *
     */
    std::vector<std::byte> priv_key_;
};

static_assert(concepts::Insertable<Insertable>);

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
class LIBHYPHANET_EXPORT Subspace_key : public Key {
public:
    /**
     * @brief Constructs a Subspace_key object with specified key
     * parameters and document name.
     *
     * @details
     * This constructor initializes a Subspace_key object with the
     * provided key parameters, which include the routing key,
     * cryptographic key, cryptographic algorithm, and any associated
     * meta strings. Additionally, it sets the document name which is
     * used to generate a routing key. The Subspace_key is a subtype of
     * Key that encodes a document name into it, which will later be
     * used to generate a routing key.
     *
     * @param key A Key_params structure containing the initial
     * parameters for the Subspace_key object.
     * @param docname A string_view representing the document name to be
     * associated with the Subspace_key.
     *
     * @throws exception::Malformed_uri If any of the provided key
     * parameters are invalid, this constructor will invoke
     * check_invariants() which may throw an exception.
     */
    Subspace_key(Key_params key, std::string_view docname)
        : Key{std::move(key)},
          docname_(docname)
    {
        check_invariants();

        // SSK always uses algo_aes_pcfb_256_sha_256
        set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);

        Key::get_routing_key().reserve(routing_key_size);
    }

    explicit Subspace_key(Token t)
        : Key{t}
    {}

    Subspace_key() = delete;
    Subspace_key(const Subspace_key& other) = default;
    Subspace_key(Subspace_key&& other) noexcept = default;
    Subspace_key& operator=(const Subspace_key& other) = default;
    Subspace_key& operator=(Subspace_key&& other) noexcept = default;
    ~Subspace_key() override = default;

    [[nodiscard]] std::string get_docname() const { return docname_; }

    /**
     * @brief Generates the Uri for a Subspace Key.
     *
     * @details
     * Constructs a Uri that includes the routing key, crypto key,
     * algorithm, and document name. This URI can be used to retrieve or
     * identify the content associated with this Subspace Key.
     *
     * If the Key is an insertable key, the routing key of the URI is
     * the private key.
     *
     * @return Uri The URI representing this Subspace Key.
     */
    [[nodiscard]] virtual Uri to_uri() const;

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
    static const size_t routing_key_size =
        32; // TODO: same as Node_ssk::pubkey_hash_size

protected:
    void init_from_uri(const Uri& uri) override;

    /**
     * @brief Retrieves additional bytes that are part of the Key's URI
     * representation.
     *
     * @details
     * This method is used to obtain a vector of bytes that represent
     * additional data required for the Key's URI. This data typically
     * includes information such as the version of the key, flags
     * indicating whether the key is for insertion or retrieval, the
     * cryptographic algorithm used, and other key-specific metadata.
     * The exact contents and format of the extra bytes are determined
     * by the specific type of Key and are used in constructing the full
     * URI for the Key.
     *
     * @return A vector of std::byte containing the extra data for the
     * Key's URI.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_extra_bytes() const;

    void set_docname(std::string_view docname) { docname_ = docname; }

private:
    void check_invariants() const;

    /**
     * @brief Document name.
     *
     * @details
     * A docname (sometimes called site name) is a part of the address
     * that provides a human-readable name for the file. It will later
     * be used to generate a [Node Routing
     * Key](#node::Node_key#node_routing_key_).
     *
     * A docname with an empty string is allowed though not recommended.
     *
     * @see
     * - Ssk#encrypted_hashed_docname_
     * - Key#routing_key_
     * - Key#crypto_key_
     */
    std::string docname_;
};

// Forward declaction
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
class LIBHYPHANET_EXPORT Ssk : public Subspace_key {
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
    static constexpr auto separator = '-';

    /**
     * @brief Constructs an Ssk (Signed Subspace Key) object with
     * specified key parameters, document name, and an optional public
     * key.
     *
     * @details
     * This constructor initializes an Ssk object with the provided key
     * parameters, which include the routing key, cryptographic key,
     * cryptographic algorithm, and any associated meta strings.
     * Additionally, it sets the document name which is used to generate
     * a routing key. The Ssk is a subtype of Key that includes a public
     * key for verification of content updates. If a public key is
     * provided, it is used to set the public key of the Ssk; otherwise,
     * the Ssk is initialized without a public key.
     *
     * @param key A Key_params structure containing the initial
     * parameters for the Ssk object.
     * @param docname A string_view representing the document name to be
     * associated with the Ssk.
     * @param pub_key An optional vector of bytes representing the
     * public key, used for content verification.
     */
    Ssk(Key_params key,
        std::string_view docname,
        const std::vector<std::byte>& pub_key = {})
        : Subspace_key{std::move(key), docname},
          pub_key_{pub_key}
    {
        calculate_encrypted_hashed_docname();
        check_invariants();
    }

    explicit Ssk(Token t)
        : Subspace_key{t}
    {}

    Ssk() = delete;
    Ssk(const Ssk& other) = default;
    Ssk(Ssk&& other) noexcept = default;
    Ssk& operator=(const Ssk& other) = default;
    Ssk& operator=(Ssk&& other) noexcept = default;
    ~Ssk() override = default;

    [[nodiscard]] Uri to_uri() const override;

    /**
     * @brief Generates the request URI for a SSK.
     *
     * @details
     * A request URI is a URI that is used to request content from the
     * network. It does not contain the private key.
     *
     * If the Ssk is an Insertable_ssk, this method computes the request
     * URI which belongs to it. Otherwise it's identical to
     * Ssk#to_uri().
     *
     * If you want to give people access to content at an URI, you
     * should always publish only the request URI. Never give away the
     * insert URI, this allows anyone to insert under your URI!
     *
     * @return Uri The request URI for this SSK.
     */
    [[nodiscard]] virtual Uri to_request_uri() const;

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
     * @return A Usk object if the conversion is successful, or a nullptr if
     * the document name does not include an edition number or does not
     * follow the expected format.
     */
    [[nodiscard]] std::unique_ptr<Usk> to_usk() const;

    [[nodiscard]] std::unique_ptr<node::Key> get_node_key() const;

    [[nodiscard]] std::vector<std::byte> get_pub_key() const
    {
        return pub_key_;
    }

protected:
    void init_from_uri(const Uri& uri) override;
    void set_pub_key(const std::vector<std::byte>& pub_key);

private:
    /**
     * @brief Calculates and stores the encrypted and hashed version of
     * the document name.
     *
     * @details
     * This method hashes the document name using SHA-256 and then
     * encrypts the hash using AES-256 with the cryptographic key of the
     * Ssk. The result is stored in the `encrypted_hashed_docname_`
     * member variable. This encrypted hash is used as part of the URI
     * for the Ssk and is necessary for certain network operations.
     */
    void calculate_encrypted_hashed_docname();

    void check_invariants() const;

    [[nodiscard]] std::optional<std::pair<std::string, long>>
    parse_sitename_edition() const;

    /**
     * @brief Stores the encrypted and hashed version of the document
     * name.
     *
     * @details
     * This array holds the result of hashing the document name with
     * SHA-256 and then encrypting it using AES-256. It is used as part
     * of the URI for the Ssk and is necessary for certain network
     * operations, such as retrieving the associated content.
     */
    std::array<std::byte, 32> encrypted_hashed_docname_{};

    /**
     * @brief Optionally stores the public key associated with the Ssk.
     *
     * @details
     * This variable holds the public key if it is provided during the
     * construction of the Ssk. The public key is used for verifying the
     * authenticity of content updates in the network. If the public key is
     * not provided, this variable remains empty.
     */
    std::vector<std::byte> pub_key_;
};

static_assert(concepts::Ssk<Ssk, Usk>);

/**
 * @brief An insertable version of an Ssk, containing a private key for
 * data insertion.
 *
 * @details
 * Insertable SSKs allow users to insert new versions of data into the
 * Hyphanet network. They are crucial for maintaining mutable content
 * where the owner wishes to update the content securely.
 */
class LIBHYPHANET_EXPORT Insertable_ssk : public Ssk, public Insertable {
public:
    /**
     * @brief Constructs an Insertable_ssk object with specified key
     * parameters, document name, and private key.
     *
     * @details
     * This constructor initializes an Insertable_ssk object with the
     * provided key parameters, which include the routing key,
     * cryptographic key, cryptographic algorithm, and any associated
     * meta strings. Additionally, it sets the document name and the
     * private key which are used to insert new versions of data into
     * the network. The Insertable_ssk is a subtype of Ssk that allows
     * for the insertion of new data versions.
     *
     * @param key A Key_params structure containing the initial
     * parameters for the Insertable_ssk object.
     * @param docname A string_view representing the document name to be
     * associated with the Insertable_ssk.
     * @param priv_key A vector of bytes representing the private key,
     * used for data insertion.
     */
    Insertable_ssk(
        Key_params key,
        std::string_view docname,
        const std::vector<std::byte>& priv_key
    )
        : Ssk{std::move(key), docname},
          Insertable(priv_key)
    {}

    /**
     * @brief Constructs an Insertable_ssk object from an existing Ssk
     * object and a private key.
     *
     * @details
     * This constructor creates an Insertable_ssk object by copying the
     * properties of an existing Ssk object and setting the private key.
     * It is used when an Ssk already exists and needs to be made
     * insertable by providing the private key for data insertion.
     *
     * @param ssk An Ssk object from which to copy the properties.
     * @param priv_key A vector of bytes representing the private key,
     * used for data insertion.
     */
    Insertable_ssk(Ssk ssk, const std::vector<std::byte>& priv_key)
        : Ssk{std::move(ssk)},
          Insertable{priv_key}
    {}

    explicit Insertable_ssk(Token t)
        : Ssk{t},
          Insertable{t}
    {}

    Insertable_ssk() = delete;
    Insertable_ssk(const Insertable_ssk& other) = default;
    Insertable_ssk(Insertable_ssk&& other) noexcept = default;
    Insertable_ssk& operator=(const Insertable_ssk& other) = default;
    Insertable_ssk& operator=(Insertable_ssk&& other) noexcept = default;
    ~Insertable_ssk() override = default;

    [[nodiscard]] Uri to_uri() const override;
    [[nodiscard]] Uri to_request_uri() const override;

protected:
    void init_from_uri(const Uri& uri) override;
    [[nodiscard]] std::vector<std::byte> get_extra_bytes() const override;
};

static_assert(concepts::Insertable_Ssk<Insertable_ssk, Usk>);

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
class LIBHYPHANET_EXPORT Usk : public Subspace_key {
public:
    Usk(Key_params key, std::string_view docname, long suggested_edition = -1)
        : Subspace_key{std::move(key), docname},
          suggested_edition_(suggested_edition)
    {}

    explicit Usk(Token t)
        : Subspace_key{t}
    {}

    Usk() = delete;
    Usk(const Usk& other) = default;
    Usk(Usk&& other) noexcept = default;
    Usk& operator=(const Usk& other) = default;
    Usk& operator=(Usk&& other) noexcept = default;
    ~Usk() override = default;

    [[nodiscard]] long get_suggested_edition() const
    {
        return suggested_edition_;
    }

    [[nodiscard]] Uri to_uri() const override;

    /**
     * @brief Generates the request URI for a Subspace Key.
     *
     * @details
     * A request URI is a URI that is used to request content from the
     * network. It does not contain the private key.
     *
     * If the Usk is an Insertable_usk, this method computes the request
     * URI which belongs to it. Otherwise it's identical to
     * Usk#to_uri().
     *
     * If you want to give people access to content at an URI, you
     * should always publish only the request URI. Never give away the
     * insert URI, this allows anyone to insert under your URI!
     *
     * @return Uri The request URI for this Subspace Key.
     */
    [[nodiscard]] virtual Uri to_request_uri() const;

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
    [[nodiscard]] std::unique_ptr<Ssk> to_ssk() const;

protected:
    void init_from_uri(const Uri& uri) override;

private:
    /**
     * @brief Suggestion edition.
     *
     * @details
     * A suggestion edition in **USK** allows the user to request
     * the latest version of a file without knowing the exact
     * **[SSK](#Ssk)** of the file. It is a number that is appended to
     * the USK after a slash, such as
     * `freenet:USK@~Alice/MyBlog/2024-01-02.html/5`. It tells the
     * client which edition of the file to start looking for. If the
     * client finds a newer edition, it will automatically switch to it.
     * The suggestion edition can be updated manually by the user, or
     * automatically by the client.
     *
     * The suggestion edition in **USK** is useful for creating dynamic
     * content on Hyphanet, such as blogs, forums, or wikis. It allows
     * the owner of the file to update the content with a new
     * **[SSK](#Ssk)**, and the users to access the updated content with
     * the same **USK**. It also helps to reduce the network load, as
     * the client does not have to search for all possible editions of
     * the file.
     *
     * `-1` in suggest edition means that the client will try to
     * find the highest edition number available for the file, starting
     * from zero and incrementing by one until it fails. This way, the
     * user can always get the most recent version of the file without
     * knowing the exact edition number.
     */
    long suggested_edition_{-1};
};

static_assert(concepts::Usk<Usk, Ssk>);

/**
 * @brief An insertable version of a Usk, containing a private key for
 * data insertion.
 *
 * @details
 * Similar to Insertable SSKs, Insertable USKs allow for the insertion
 * of new data versions but with the added functionality of USKs for
 * dynamic content updates.
 */
class LIBHYPHANET_EXPORT Insertable_usk : public Usk, public Insertable {
public:
    /**
     * @brief Constructs an Insertable_usk object from an existing Usk
     * object and a private key.
     *
     * @details
     * This constructor creates an Insertable_usk object by copying the
     * properties of an existing Usk object and setting the private key.
     * It is used when an Usk already exists and needs to be made
     * insertable by providing the private key for data insertion. The
     * Insertable_usk inherits from both Usk and Insertable, combining
     * the functionality of an Updatable Subspace Key with the ability
     * to insert new versions of data into the network.
     *
     * @param usk An Usk object from which to copy the properties.
     * @param priv_key A vector of bytes representing the private key,
     * used for data insertion.
     */
    Insertable_usk(Usk usk, const std::vector<std::byte>& priv_key)
        : Usk(std::move(usk)),
          Insertable(priv_key)
    {}

    explicit Insertable_usk(Token t)
        : Usk{t},
          Insertable{t}
    {}

    Insertable_usk() = delete;

    [[nodiscard]] Uri to_request_uri() const override;

protected:
    void init_from_uri(const Uri& uri) override;
    [[nodiscard]] std::vector<std::byte> get_extra_bytes() const override;
};

static_assert(concepts::Insertable_Usk<Insertable_usk, Ssk>);

/**
 * @brief Represents a **Keyword Signed %Key** (KSK) in the Hyphanet
 * network.
 *
 * @details
 * KSKs are a simple form of keys that are derived directly from a
 * human-readable string. They are less secure than SSKs or USKs but
 * offer a straightforward way to share and access static content.
 */
class LIBHYPHANET_EXPORT Ksk : public Insertable_ssk {
public:
    explicit Ksk(std::string keyword);

    explicit Ksk(Token t)
        : Insertable_ssk{t}
    {}

    Ksk() = delete;

    [[nodiscard]] Uri to_uri() const override;

    /**
     * @brief Generates the request URI for a Ksk.
     *
     * @details
     * It's identical to Ksk#to_uri() as it's its own insertable URI.
     *
     * @return Uri The request URI for this Ksk.
     */
    [[nodiscard]] Uri to_request_uri() const override;

protected:
    void init_from_uri(const Uri& uri) override;

private:
    /**
     * @brief The keyword from which the KSK is derived.
     */
    std::string keyword_;
};

static_assert(concepts::Ksk<Ksk, Usk>);

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
class LIBHYPHANET_EXPORT Chk : public Key {
public:
    /**
     * @brief Construct a new **Content Hash %Key** (CHK) object.
     *
     * @param key Key_params including routing key, crypto key, and
     * algorithm.
     * @param control_document Flag indicating if the content is a
     * control document.
     * @param compressor Compression algorithm used on the content.
     */
    Chk(Key_params key,
        bool control_document,
        support::compressor::Compressor_type compressor)
        : Key(std::move(key)),
          control_document_(control_document),
          compressor_(compressor)
    {}

    explicit Chk(Token t)
        : Key{t}
    {}

    Chk() = delete;

    /**
     * @brief Generates the URI for a Content Hash Key (CHK).
     *
     * @details
     * Constructs a URI that includes the routing key, crypto key,
     * control document flag, and compression algorithm. This URI can be
     * used to retrieve or identify the content associated with this
     * CHK.
     *
     * @return Uri The URI representing this CHK.
     */
    [[nodiscard]] Uri to_uri() const;

    /**
     * @brief Generates the request URI for a Chk.
     *
     * @details
     * It's identical to Chk#to_uri() as it's its own insertable URI.
     *
     * @return Uri The request URI for this Chk.
     */
    [[nodiscard]] Uri to_request_uri() const;

    /**
     * @brief Returns the node key associated with this CHK.
     *
     * @details
     * Generates a node key based on the routing key. This key is used
     * at the node level to locate and retrieve the content.
     *
     * @return The node::Node_key associated with this CHK.
     */
    [[nodiscard]] std::unique_ptr<node::Key> get_node_key() const;

    [[nodiscard]] bool get_control_document() const
    {
        return control_document_;
    }

    [[nodiscard]] support::compressor::Compressor_type get_compressor() const
    {
        return compressor_;
    }

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
    static const short routing_key_size = 32;

protected:
    void init_from_uri(const Uri& uri) override;

private:
    /**
     * @brief Parses and sets the encryption algorithm from a byte.
     *
     * @param algo_byte The byte representing the encryption algorithm.
     */
    void parse_algo(std::byte algo_byte);

    /**
     * @brief Parses and sets the compression algorithm from two bytes.
     *
     * @param byte_1 The first byte of the compression algorithm.
     * @param byte_2 The second byte of the compression algorithm.
     */
    void parse_compressor(std::byte byte_1, std::byte byte_2);

    /**
     * @brief Generates the extra bytes for the CHK URI.
     *
     * @details
     * Constructs the extra data section of the URI, which includes the
     * encryption algorithm, control document flag, and compression
     * algorithm.
     *
     * @return A vector of bytes representing the extra data for the CHK
     * URI.
     */
    [[nodiscard]] std::vector<std::byte> get_extra_bytes() const;

    /**
     * @brief Indicates if this is a control document.
     */
    bool control_document_{false};

    /**
     * @brief Compression type used.
     */
    support::compressor::Compressor_type compressor_{
        support::compressor::Compressor_type::gzip
    };
};

static_assert(concepts::Chk<Chk>);

inline void init_from_url(Key& key, const Uri& uri)
{
    key.init_from_uri(uri);
}

template<typename T, typename U>
inline constexpr bool always_false_v = false;

template<concepts::Key T, concepts::Key Key_type>
[[nodiscard]] std::shared_ptr<T> create_and_init_key(const Uri& uri)
{
    const Key::Token t{};
    auto key = std::make_shared<Key_type>(t);

    init_from_url(*key, uri);
    if constexpr (std::is_same_v<T, Any_key>) {
        return std::make_shared<T>(key);
    }
    else if constexpr (std::is_base_of_v<T, Key_type>) {
        return key;
    }
    else {
        return nullptr;
    }
}

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
template<concepts::Key T>
[[nodiscard]] LIBHYPHANET_EXPORT std::shared_ptr<T> create(const Uri& uri)
{
    bool is_insertable{false};
    if (auto extra = uri.get_extra();
        !extra.empty() && extra.size() >= 5 && extra.at(1) == std::byte{1}) {
        is_insertable = true;
    }

    switch (uri.get_uri_type()) {
        using enum key::Uri_type;
    case usk:
        if (is_insertable) {
            return create_and_init_key<T, Insertable_usk>(uri);
        }
        else {
            return create_and_init_key<T, Usk>(uri);
        }
    case ssk:
        if (is_insertable) {
            return create_and_init_key<T, Insertable_ssk>(uri);
        }
        else {
            return create_and_init_key<T, Ssk>(uri);
        }
    case chk: {
        return create_and_init_key<T, Chk>(uri);
    }
    case ksk: {
        return create_and_init_key<T, Ksk>(uri);
    }
    default:
        throw exception::Malformed_uri{"Invalid URI: unknown key type"};
    }
}

const auto create_key = create<Any_key>;

} // namespace key::user

#endif /* LIBHYPHANET_KEY_USER_H */
