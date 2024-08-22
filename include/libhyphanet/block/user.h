#ifndef LIBHYPHANET_BLOCK_USER_H
#define LIBHYPHANET_BLOCK_USER_H

#include "libhyphanet/block/node.h"
#include "libhyphanet/bucket.h"
#include "libhyphanet/bucket/random.h"
#include "libhyphanet/key/node.h"
#include "libhyphanet/key/user.h"
#include "libhyphanet/support.h"

#include <cstddef>
#include <memory>
#include <vector>

namespace block::user {
namespace concepts {
    /**
     * @brief Does the block contain metadata? If not, it contains real
     * data.
     */
    template<typename T>
    concept Has_Is_Metadata = requires(T t) {
        { t.is_metadata() } -> std::same_as<bool>;
    };

    template<typename T>
    concept Has_Memory_Decode = requires(const T t) {
        { t.memory_decode() } -> std::same_as<std::vector<std::byte>>;
    };

    /**
     * @brief Get the key::user::Key for this block.
     *
     * @return std::shared_ptr<key::user::Key> The key::user::Key object
     */
    template<typename T>
    concept Has_Get_User_Key = requires(T t) {
        { t.get_user_key() } -> std::same_as<std::shared_ptr<key::user::Key>>;
    };

    /**
     * @brief Get the node key for this block.
     *
     * @return std::shared_ptr<key::node::Key> The node key
     */
    template<typename T>
    concept Has_Get_Node_Block = requires(T t) {
        {
            t.get_node_block()
        } -> std::same_as<std::shared_ptr<block::node::Key>>;
    };

    /**
     * @brief Returns the node key corresponding to this key.
     *
     * @return The node key as a `node::Node_key` object.
     */
    template<typename T>
    concept Has_Get_Node_Key = requires(const T t) {
        { t.get_node_key() } -> std::same_as<std::unique_ptr<key::node::Key>>;
    };

    template<typename T, typename Bucket, typename Bucket_factory>
    concept Has_Decode =
        bucket::concepts::Bucket<Bucket>
        && bucket::random::concepts::Factory<Bucket_factory, Bucket>
        && requires(
            T t, Bucket_factory bf, size_t max_length, bool dont_decompress
        ) {
               {
                   t.decode(bf, max_length, dont_decompress)
               } -> std::same_as<std::unique_ptr<Bucket>>;
           };

    /**
     * @brief A Key Block with a key::user::Key. Can be decoded. Not a child of
     * data::block::node::Key because of issues with equals.
     *
     * @details
     * Two user key blocks with the same content but different keys are not
     * equals, therefore a user key block and its node key block have to be
     * not equals too. Hence it's really a different kind of object, so not a
     * child.
     */
    template<typename T>
    concept Key = Has_Is_Metadata<T> && Has_Memory_Decode<T>;

    template<typename T>
    concept Chk = Key<T>;

    template<typename T>
    concept Has_Max_Decompressed_Data_Length = requires {
        { T::max_decompressed_data_length } -> std::convertible_to<size_t>;
    };

    template<typename T>
    concept Ssk = Key<T> && Has_Max_Decompressed_Data_Length<T>;

} // namespace concepts

[[nodiscard]] LIBHYPHANET_EXPORT key::user::concepts::Key_Shared_Ptr auto
get_user_key(concepts::Key auto& block_key)
{
    return block_key.get_user_key();
}

[[nodiscard]] LIBHYPHANET_EXPORT node::concepts::Key_Shared_Ptr auto
get_node_block(concepts::Key auto& block_key)
{
    return block_key.get_node_block();
}

[[nodiscard]] LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
get_node_key(concepts::Key auto& block_key)
{
    return block_key.get_node_key();
}

class Chk {
public:
    friend LIBHYPHANET_EXPORT key::user::concepts::Key auto
    get_user_key(concepts::Key auto& block_key);

    friend LIBHYPHANET_EXPORT node::concepts::Key_Shared_Ptr auto
    get_node_block(concepts::Key auto& block_key);

    friend LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
    get_node_key(concepts::Key auto& block_key);

    /**
     * @brief Decode the key into RAM, if short.
     *
     * @return std::vector<std::byte>
     */
    [[nodiscard]] std::vector<std::byte> memory_decode() const;

    [[nodiscard]] static bool is_metadata() { return false; }

private:
    /**
     * @brief Get the key::user::Key for this block.
     *
     * @return std::shared_ptr<key::user::Key> The key::user::Key object
     */
    [[nodiscard]] std::shared_ptr<key::user::Chk> get_user_key() const
    {
        return user_key_;
    }

    /**
     * @brief Get the node key block for this block.
     *
     * @return std::shared_ptr<block::node::Key> The node key block
     */
    [[nodiscard]] std::shared_ptr<block::node::Chk> get_node_block() const
    {
        return node_block_;
    }

    /**
     * @brief Get the node key for this block.
     *
     * @return std::shared_ptr<key::node::Key> The node key
     */
    [[nodiscard]] std::shared_ptr<key::node::Chk> get_node_key() const
    {
        return node::get_node_key(*node_block_);
    }

    std::shared_ptr<key::user::Chk> user_key_;
    std::shared_ptr<block::node::Chk> node_block_;
};

static_assert(concepts::Key<Chk>);

class Ssk {
public:
    friend LIBHYPHANET_EXPORT key::user::concepts::Key auto
    get_user_key(concepts::Key auto& block_key);

    friend LIBHYPHANET_EXPORT node::concepts::Key_Shared_Ptr auto
    get_node_block(concepts::Key auto& block_key);

    friend LIBHYPHANET_EXPORT key::node::concepts::Key_Shared_Ptr auto
    get_node_key(concepts::Key auto& block_key);

    /**
     * @brief Decode the key into RAM, if short.
     *
     * @return std::vector<std::byte>
     */
    [[nodiscard]] std::vector<std::byte> memory_decode() const;

    [[nodiscard]] static bool is_metadata() { return false; }

    static const size_t max_decompressed_data_length = 32768;

private:
    /**
     * @brief Get the key::user::Key for this block.
     *
     * @return std::shared_ptr<key::user::Key> The key::user::Key object
     */
    [[nodiscard]] std::shared_ptr<key::user::Ssk> get_user_key() const
    {
        return user_key_;
    }

    /**
     * @brief Get the node key block for this block.
     *
     * @return std::shared_ptr<block::node::Key> The node key block
     */
    [[nodiscard]] std::shared_ptr<block::node::Ssk> get_node_block() const
    {
        return node_block_;
    }

    /**
     * @brief Get the node key for this block.
     *
     * @return std::shared_ptr<key::node::Key> The node key
     */
    [[nodiscard]] std::shared_ptr<key::node::Ssk> get_node_key() const
    {
        return node::get_node_key(*node_block_);
    }

    std::shared_ptr<key::user::Ssk> user_key_;
    std::shared_ptr<block::node::Ssk> node_block_;

    /**
     * @brief Is metadata. Set on decode.
     */
    bool is_metadata_;

    /**
     * @brief Has decoded?
     */
    bool decoded_;

    support::compressor::Compressor_type compression_algorithm_;
};

static_assert(concepts::Key<Ssk>);

} // namespace block::user

#endif /* LIBHYPHANET_BLOCK_USER_H */
