#ifndef LIBHYPHANET_BUCKET_RANDOM_H
#define LIBHYPHANET_BUCKET_RANDOM_H

#include "libhyphanet/bucket.h"
#include <cstddef>
#include <libhyphanet/libhyphanet_export.h>
#include <memory>

namespace bucket::random {

/**
 * @brief A Bucket which can be converted to a LockableRandomAccessBuffer
 * without copying.
 *
 * @details
 * Mostly we need
 * this where the size of something we will later use as a RandomAccessBuffer is
 * uncertain. It provides a separate object because the API's are incompatible;
 * in particular, the size of a RandomAccessBuffer is fixed (and this is mostly
 * a good thing).
 *
 * FINALIZERS: Persistent RandomAccessBucket's should never free on finalize.
 * Transient RABs can free on finalize, but must ensure that this only happens
 * if both the Bucket and the RAB are no longer reachable.
 *
 */
class LIBHYPHANET_EXPORT Random_access : public virtual Bucket {
public:
    // TODO: toRandomAccessBuffer()
};

class LIBHYPHANET_EXPORT Array : public virtual Random_access {};

class LIBHYPHANET_EXPORT Factory {
public:
    virtual ~Factory() = default;

    /**
     * @brief Create a bucket.
     *
     * @param size The maximum size of the data, or -1 if we don't know.
     * Some buckets will throw IOException if you go over this length.
     *
     * @return Random_access a Random Access Bucket
     */
    [[nodiscard]] virtual std::unique_ptr<Random_access>
    make_bucket(size_t size) const = 0;
};

namespace impl {

    class Array_read_stream;
    class Array_write_stream;

    class Array : public virtual bucket::random::Array,
                  public bucket::impl::Bucket {
    public:
        friend class Array_read_stream;
        friend class Array_write_stream;

        Array(const std::vector<std::byte>& init_data = {},
              std::string_view name = "ArrayBucket")
            : data_{init_data}
        {
            set_name(name);
        }

        [[nodiscard]] std::unique_ptr<Array_read_stream> get_read_stream(
            const std::shared_ptr<boost::asio::io_context>& io_context) const
        {
            return std::make_unique<Array_read_stream>(
                io_context, std::make_shared<const Array>(this));
        }

        [[nodiscard]] std::unique_ptr<Array_write_stream> get_write_stream(
            const std::shared_ptr<boost::asio::io_context>& io_context) const
        {
            return std::make_unique<Array_write_stream>(
                io_context, std::make_shared<Array>(this));
        }

        [[nodiscard]] size_t size() const override { return data_.size(); }
    private:
        std::vector<std::byte> data_;
    };

    class Array_read_stream : public Read_stream<Array_read_stream> {
    public:
        explicit Array_read_stream(
            std::shared_ptr<boost::asio::io_context> io_context,
            std::shared_ptr<const Array> array)
            : Read_stream<Array_read_stream>{std::move(io_context)},
              array_{std::move(array)}
        {}

        /**
         * @brief Start an asynchronous read.
         *
         * @details
         * It's a requirement of AsyncReadStream.
         */
        template<typename Mutable_buffer_sequence, typename Read_handler>
        void async_read_some(const Mutable_buffer_sequence& buffers,
                             Read_handler&& handler)
        {
            auto bytes_available = array_->data_.size() - read_position_;
            auto bytes_to_read
                = std::min(bytes_available, boost::asio::buffer_size(buffers));

            std::copy(
                array_->data_.begin() + gsl::narrow_cast<long>(read_position_),
                array_->data_.begin() + gsl::narrow_cast<long>(read_position_)
                    + bytes_to_read,
                static_cast<std::byte*>(buffers.data()));

            read_position_ += bytes_to_read;

            // Schedule the completion handler
            boost::asio::post(
                get_io_context(),
                [handler_fwd = std::forward<Read_handler>(handler),
                 bytes_to_read]() mutable {
                    handler_fwd(boost::system::error_code{}, bytes_to_read);
                });
        }
    private:
        std::shared_ptr<const Array> array_;
        std::size_t read_position_ = 0;
    };

    class Array_write_stream : public Write_stream<Array_write_stream> {
    public:
        explicit Array_write_stream(
            std::shared_ptr<boost::asio::io_context> io_context,
            std::shared_ptr<Array> array)
            : Write_stream<Array_write_stream>{std::move(io_context)},
              array_{std::move(array)}
        {}

        /**
         * @brief Start an asynchronous write.
         *
         * @details
         * It's a requirement of AsyncWriteStream.
         */
        template<typename Const_buffer_sequence, typename Write_handler>
        void async_write_some(const Const_buffer_sequence& buffers,
                              Write_handler&& handler)
        {
            std::size_t bytes_transferred = 0;
            for (const auto& buffer:
                 boost::asio::buffer_sequence_begin(buffers),
                 boost::asio::buffer_sequence_end(buffers)) {
                const auto begin = static_cast<const std::byte*>(buffer.data());
                const std::byte* end = begin + buffer.size();
                array_->data_.insert(array_->data_.end(), begin, end);
                bytes_transferred += buffer.size();
            }

            boost::asio::post(
                get_io_context(),
                [handler_fwd = std::forward<Write_handler>(handler),
                 bytes_transferred]() mutable {
                    handler_fwd(boost::system::error_code(), bytes_transferred);
                });
        }
    private:
        std::shared_ptr<Array> array_;
    };
} // namespace impl
namespace factory {
    class LIBHYPHANET_EXPORT Array_factory : public Factory {
    public:
        [[nodiscard]] std::unique_ptr<Random_access>
        make_bucket(size_t /*size*/) const override
        {
            return std::make_unique<impl::Array>();
        }
    };
} // namespace factory

} // namespace bucket::random
#endif /* LIBHYPHANET_BUCKET_RANDOM_H */
