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

namespace key::user::impl {
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
class Key : public virtual key::user::Key {
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
        : routing_key_(std::move(key.routing_key)), crypto_key_(key.crypto_key),
          crypto_algorithm_(key.crypto_algorithm),
          meta_strings_(key.meta_strings)
    {
        check_invariants();
    }

    explicit Key(Token /*unused*/) {}
    Key() = delete;

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
     * @brief Returns the routing key of the Key object.
     *
     * @return The routing key as a vector of bytes.
     */
    [[nodiscard]] std::vector<std::byte> get_routing_key() const override
    {
        return routing_key_;
    }

    /**
     * @brief Returns the crypto key of the Key object.
     *
     * @return The crypto key as an array of bytes.
     */
    [[nodiscard]] std::array<std::byte, crypto_key_length>
    get_crypto_key() const final
    {
        return crypto_key_;
    }

    /**
     * @brief Returns the cryptographic algorithm used by the Key
     * object.
     *
     * @return The crypto algorithm as an enum value.
     */
    [[nodiscard]] Crypto_algorithm get_crypto_algorithm() const override
    {
        return crypto_algorithm_;
    }

    /**
     * @brief Returns the meta strings associated with the Key object.
     *
     * @return A constant reference to the vector of meta strings.
     */
    [[nodiscard]] const std::vector<std::string>&
    get_meta_strings() const override
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
     * @return An optional containing the first meta string if
     * available, or std::nullopt if there are no meta strings left.
     */
    std::optional<std::string> pop_meta_strings();
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
        Crypto_algorithm::algo_aes_pcfb_256_sha_256};

    std::vector<std::string> meta_strings_;
};

/**
 * @brief A mixin class for Insertable Keys.
 *
 * @details
 * A Insertable key contains a private key from the [Key](#Key) owner,
 * so a user can use it to insert new versions of data.
 */
class Insertable : public virtual key::user::Insertable {
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

    /**
     * @brief Return the private key for the current Key.
     *
     * @return The private key as a vector of bytes.
     */
    [[nodiscard]] std::vector<std::byte> get_priv_key() const override
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
class Subspace_key : public virtual key::user::Subspace_key, public Key {
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
        : key::user::impl::Key{std::move(key)}, docname_(docname)
    {
        check_invariants();

        // SSK always uses algo_aes_pcfb_256_sha_256
        set_crypto_algorithm(Crypto_algorithm::algo_aes_pcfb_256_sha_256);

        key::user::impl::Key::get_routing_key().reserve(routing_key_size);
    }

    explicit Subspace_key(Token t): key::user::impl::Key{t} {}
    Subspace_key() = delete;

    [[nodiscard]] std::string get_docname() const override { return docname_; }

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
    [[nodiscard]] Uri to_uri() const override;
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
class Ssk : public virtual key::user::Ssk, public Subspace_key {
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
    Ssk(Key_params key, std::string_view docname,
        const std::optional<const std::vector<std::byte>>& pub_key
        = std::nullopt)
        : key::user::impl::Subspace_key{std::move(key), docname},
          pub_key_{pub_key}
    {
        calculate_encrypted_hashed_docname();
        check_invariants();
    }

    explicit Ssk(Token t): key::user::impl::Subspace_key{t} {}
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
    [[nodiscard]] Uri to_request_uri() const override;

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
    [[nodiscard]] std::optional<std::unique_ptr<key::user::Usk>>
    to_usk() const override;

    [[nodiscard]] std::unique_ptr<node::Key> get_node_key() const override;

    [[nodiscard]] std::optional<std::vector<std::byte>>
    get_pub_key() const override
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
     * This optional variable holds the public key if it is provided
     * during the construction of the Ssk. The public key is used for
     * verifying the authenticity of content updates in the network. If
     * the public key is not provided, this variable remains empty.
     */
    std::optional<std::vector<std::byte>> pub_key_;
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
class Insertable_ssk : public virtual key::user::Insertable_ssk,
                       public Ssk,
                       public Insertable {
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
    Insertable_ssk(Key_params key, std::string_view docname,
                   const std::vector<std::byte>& priv_key)
        : key::user::impl::Ssk{std::move(key), docname},
          key::user::impl::Insertable(priv_key)
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
    Insertable_ssk(key::user::impl::Ssk ssk,
                   const std::vector<std::byte>& priv_key)
        : key::user::impl::Ssk{std::move(ssk)},
          key::user::impl::Insertable{priv_key}
    {}

    explicit Insertable_ssk(Token t)
        : key::user::impl::Ssk{t}, key::user::impl::Insertable{t}
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
class Usk : public virtual key::user::Usk, public Subspace_key {
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

    [[nodiscard]] long get_suggested_edition() const override
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
    [[nodiscard]] Uri to_request_uri() const override;

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
    [[nodiscard]] std::unique_ptr<key::user::Ssk> to_ssk() const override;
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

/**
 * @brief An insertable version of a Usk, containing a private key for
 * data insertion.
 *
 * @details
 * Similar to Insertable SSKs, Insertable USKs allow for the insertion
 * of new data versions but with the added functionality of USKs for
 * dynamic content updates.
 */
class Insertable_usk : public virtual key::user::Insertable_usk,
                       public Usk,
                       public Insertable {
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
        : Usk(std::move(usk)), Insertable(priv_key)
    {}

    explicit Insertable_usk(Token t): Usk{t}, Insertable{t} {}
    Insertable_usk() = delete;

    [[nodiscard]] Uri to_request_uri() const override;
protected:
    void init_from_uri(const Uri& uri) override;
    [[nodiscard]] std::vector<std::byte> get_extra_bytes() const override;
};

/**
 * @brief Represents a **Keyword Signed %Key** (KSK) in the Hyphanet
 * network.
 *
 * @details
 * KSKs are a simple form of keys that are derived directly from a
 * human-readable string. They are less secure than SSKs or USKs but
 * offer a straightforward way to share and access static content.
 */
class Ksk : public virtual key::user::Ksk, public Insertable_ssk {
public:
    explicit Ksk(std::string keyword);

    explicit Ksk(Token t): Insertable_ssk{t} {}
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
class Chk : public virtual key::user::Chk, public Key {
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
    Chk(Key_params key, bool control_document,
        support::compressor::Compressor_type compressor)
        : Key(std::move(key)), control_document_(control_document),
          compressor_(compressor)
    {}

    explicit Chk(Token t): Key{t} {}
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
    [[nodiscard]] Uri to_uri() const override;

    /**
     * @brief Generates the request URI for a Chk.
     *
     * @details
     * It's identical to Chk#to_uri() as it's its own insertable URI.
     *
     * @return Uri The request URI for this Chk.
     */
    [[nodiscard]] Uri to_request_uri() const override;

    /**
     * @brief Returns the node key associated with this CHK.
     *
     * @details
     * Generates a node key based on the routing key. This key is used
     * at the node level to locate and retrieve the content.
     *
     * @return The node::Node_key associated with this CHK.
     */
    [[nodiscard]] std::unique_ptr<node::Key> get_node_key() const override;

    [[nodiscard]] bool get_control_document() const override
    {
        return control_document_;
    }

    [[nodiscard]] support::compressor::Compressor_type
    get_compressor() const override
    {
        return compressor_;
    }
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
        support::compressor::Compressor_type::gzip};
};
} // namespace key::user::impl

#endif /* LIBHYPHANET_KEY_USER_H */
