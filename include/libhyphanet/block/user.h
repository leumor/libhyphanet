#ifndef LIBHYPHANET_BLOCK_USER_H
#define LIBHYPHANET_BLOCK_USER_H

#include "libhyphanet/block/node.h"
#include "libhyphanet/bucket.h"
#include "libhyphanet/key/user.h"
#include <vector>

namespace block::user {
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

    // template<typename Derived>
    // [[nodiscard]] bucket::Bucket<Derived>

    /**
     * @brief Does the block contain metadata? If not, it contains real
     * data.
     */
    [[nodiscard]] virtual bool is_metadata() = 0;

    [[nodiscard]] virtual std::vector<std::byte> memory_decode() = 0;

    /**
     * @brief Get the key::user::Key for this block.
     *
     * @return std::shared_ptr<key::user::Key> The key::user::Key object
     */
    [[nodiscard]] virtual std::shared_ptr<key::user::Key> get_user_key() const
        = 0;

    /**
     * @brief Get the node key block for this block.
     *
     * @return std::shared_ptr<block::node::Key> The node key block
     */
    [[nodiscard]] virtual std::shared_ptr<block::node::Key>
    get_node_block() const = 0;

    /**
     * @brief Get the node key for this block.
     *
     * @return std::shared_ptr<key::node::Key> The node key
     */
    [[nodiscard]] virtual std::shared_ptr<key::node::Key> get_node_key() const
        = 0;
};

class Chk : public virtual Key {};

class Ssk : public virtual Key {
public:
    static const size_t max_decompressed_data_length = 32768;
};

namespace impl {
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
    class Key : public virtual block::user::Key {
    public:
        /**
         * @brief Get the key::user::Key for this block.
         *
         * @return std::shared_ptr<key::user::Key> The key::user::Key object
         */
        [[nodiscard]] std::shared_ptr<key::user::Key>
        get_user_key() const override
        {
            return user_key_;
        }

        /**
         * @brief Get the node key block for this block.
         *
         * @return std::shared_ptr<block::node::Key> The node key block
         */
        [[nodiscard]] std::shared_ptr<block::node::Key>
        get_node_block() const override
        {
            return node_block_;
        }

        /**
         * @brief Get the node key for this block.
         *
         * @return std::shared_ptr<key::node::Key> The node key
         */
        [[nodiscard]] std::shared_ptr<key::node::Key>
        get_node_key() const override
        {
            return node_block_->get_node_key();
        }
    private:
        std::shared_ptr<key::user::Key> user_key_;
        std::shared_ptr<block::node::Key> node_block_;
    };

    class Chk : public Key {};

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

} // namespace impl
} // namespace block::user

#endif /* LIBHYPHANET_BLOCK_USER_H */
