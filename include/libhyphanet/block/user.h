#ifndef LIBHYPHANET_BLOCK_USER_H
#define LIBHYPHANET_BLOCK_USER_H

#include "libhyphanet/block/node.h"
#include "libhyphanet/bucket.h"
#include "libhyphanet/bucket/random.h"
#include "libhyphanet/key/user.h"

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
    concept Has_Memory_Decode = requires(T t) {
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
    template<typename T, typename Bucket, typename Bucket_factory>
    concept Key =
        Has_Is_Metadata<T> && Has_Memory_Decode<T> && Has_Get_User_Key<T>
        && Has_Get_Node_Block<T> && Has_Decode<T, Bucket, Bucket_factory>;

    template<typename T, typename Bucket, typename Bucket_factory>
    concept Chk = Key<T, Bucket, Bucket_factory>;

    template<typename T>
    concept Has_Max_Decompressed_Data_Length = requires {
        { T::max_decompressed_data_length } -> std::convertible_to<size_t>;
    };

    template<typename T, typename Bucket, typename Bucket_factory>
    concept Ssk =
        Key<T, Bucket, Bucket_factory> && Has_Max_Decompressed_Data_Length<T>;

} // namespace concepts

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
class Key {
public:
    virtual ~Key() = default;

    /**
     * @brief Get the key::user::Key for this block.
     *
     * @return std::shared_ptr<key::user::Key> The key::user::Key object
     */
    [[nodiscard]] virtual std::shared_ptr<key::user::Key> get_user_key() const
    {
        return user_key_;
    }

    /**
     * @brief Get the node key block for this block.
     *
     * @return std::shared_ptr<block::node::Key> The node key block
     */
    [[nodiscard]] virtual std::shared_ptr<block::node::Key>
    get_node_block() const
    {
        return node_block_;
    }

    /**
     * @brief Get the node key for this block.
     *
     * @return std::shared_ptr<key::node::Key> The node key
     */
    [[nodiscard]] virtual std::shared_ptr<key::node::Key> get_node_key() const
    {
        return node_block_->get_node_key();
    }

private:
    std::shared_ptr<key::user::Key> user_key_;
    std::shared_ptr<block::node::Key> node_block_;
};

class Chk : public Key {
public:
    [[nodiscard]] virtual bool is_metadata() { return false; }
};

// TODO: Assert concpet for Chk

class Ssk : public Key {
public:
    static const size_t max_decompressed_data_length = 32768;

private:
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

// TODO: Assert concpet for Ssk

} // namespace block::user

#endif /* LIBHYPHANET_BLOCK_USER_H */
