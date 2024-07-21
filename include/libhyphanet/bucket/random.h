#ifndef LIBHYPHANET_BUCKET_RANDOM_H
#define LIBHYPHANET_BUCKET_RANDOM_H

#include "libhyphanet/bucket.h"
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <gsl/util>
#include <libhyphanet/libhyphanet_export.h>
#include <memory>
#include <utility>
#include <vector>

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
 * FINALIZER: Persistent RandomAccessBucket's should never free on finalize.
 * Transient RABs can free on finalize, but must ensure that this only happens
 * if both the Bucket and the RAB are no longer reachable.
 *
 */
class LIBHYPHANET_EXPORT Random_access : public virtual Bucket {
public:
    using executor_type = boost::asio::any_io_executor;

    // TODO: toRandomAccessBuffer()
};

class LIBHYPHANET_EXPORT Array : public virtual Random_access {};

class LIBHYPHANET_EXPORT Factory {
public:
    using executor_type = boost::asio::any_io_executor;

    virtual ~Factory() = default;

    /**
     * @brief Create a bucket.
     *
     * @param size The maximum size of the data, or -1 if we don't know.
     * Some buckets will throw IOException if you go over this length.
     *
     * @return std::unique_ptr<Random_access> a Random Access Bucket
     */
    [[nodiscard]] virtual std::shared_ptr<Random_access>
    make_bucket(size_t size) const = 0;

    [[nodiscard]] virtual boost::asio::awaitable<std::shared_ptr<Random_access>>
    make_immutable_bucket(executor_type executor, std::vector<std::byte> data,
                          size_t length, size_t offset = 0) const
        = 0;
};

template<typename Derived> class LIBHYPHANET_EXPORT Random_access_read_device {
public:
    using executor_type = boost::asio::any_io_executor;

    template<typename Mutable_buffer_sequence, typename Read_handler>
    void async_read_some_at(uint64_t offset,
                            const Mutable_buffer_sequence& buffers,
                            Read_handler&& handler)
    {
        static_cast<Derived*>(this)->async_read_some_at(
            offset, buffers, std::forward<Read_handler>(handler));
    }
};

template<typename Derived> class LIBHYPHANET_EXPORT Random_access_write_device {
public:
    using executor_type = boost::asio::any_io_executor;

    template<typename Const_buffer_sequence, typename Write_handler>
    void async_write_some_at(uint64_t offset,
                             const Const_buffer_sequence& buffers,
                             Write_handler&& handler)
    {
        static_cast<Derived*>(this)->async_write_some_at(
            offset, buffers, std::forward<Write_handler>(handler));
    }
};

template<typename T> concept DerivedFromRandomAccess
    = std::derived_from<T, Random_access>;

template<DerivedFromRandomAccess T> [[nodiscard]] std::unique_ptr<
    Random_access_read_device<typename T::reader_type>>
get_random_access_reader(const executor_type& executor,
                         const std::shared_ptr<T> bucket)
{
    return std::make_unique<typename T::reader_type>(executor, bucket);
}

template<DerivedFromRandomAccess T> [[nodiscard]] std::unique_ptr<
    Random_access_write_device<typename T::writer_type>>
get_random_access_writer(const executor_type& executor,
                         const std::shared_ptr<T> bucket)
{
    return std::make_unique<typename T::writer_type>(executor, bucket);
}

namespace impl {
    class Array_reader;
    class Array_writer;

    class Array : public virtual bucket::random::Array,
                  public bucket::impl::Bucket,
                  public std::enable_shared_from_this<Array> {
    public:
        friend class Array_reader;
        friend class Array_writer;

        using reader_type = Array_reader;
        using writer_type = Array_writer;

        Array(const std::vector<std::byte>& init_data = {},
              std::string_view name = "ArrayBucket")
            : data_{init_data}
        {
            set_name(name);
        }

        [[nodiscard]] size_t size() const override { return data_.size(); }

        [[nodiscard]] std::unique_ptr<bucket::Bucket> create_shadow() override
        {
            return nullptr;
        }
    private:
        std::vector<std::byte> data_;
    };

    class Array_reader : public Read_stream<Array_reader>,
                         public Random_access_read_device<Array_reader>,
                         public std::enable_shared_from_this<Array_reader> {
    public:
        explicit Array_reader(executor_type executor,
                              std::shared_ptr<const Array> array)
            : Read_stream<Array_reader>{std::move(executor)},
              array_{std::move(array)}
        {}

        /**
         * @brief Start an asynchronous read.
         *
         * @details
         * It's a requirement of AsyncReadStream.
         */
        // AsyncReadStream
        template<typename Mutable_buffer_sequence, typename Read_handler>
        void async_read_some(const Mutable_buffer_sequence& buffers,
                             Read_handler&& handler)
        {
            boost::asio::post(
                get_executor(),
                [this, self = shared_from_this(), buffers,
                 handler2 = std::forward<Read_handler>(handler)]() mutable {
                    do_read_some(buffers, 0, std::move(handler2));
                });
        }

        template<typename Mutable_buffer_sequence, typename Read_handler>
        // cppcheck-suppress duplInheritedMember
        void async_read_some_at(uint64_t offset,
                                const Mutable_buffer_sequence& buffers,
                                Read_handler&& handler)
        {
            boost::asio::post(
                get_executor(),
                [this, self = shared_from_this(), offset, buffers,
                 handler2 = std::forward<Read_handler>(handler)]() mutable {
                    do_read_some(buffers, offset, std::move(handler2));
                });
        }
    private:
        template<typename Mutable_buffer_sequence, typename Read_handler>
        void do_read_some(const Mutable_buffer_sequence& buffers,
                          uint64_t offset, Read_handler handler)
        {
            std::size_t bytes_transferred = 0;
            boost::system::error_code ec;

            // Use read_pos_ for stream-oriented reads, offset for random access
            // reads
            if (uint64_t read_offset = (offset == 0) ? read_pos_ : offset;
                read_offset > array_->data_.size()) {
                ec = boost::asio::error::eof;
            }
            else {
                for (const auto& buffer:
                     boost::asio::buffer_sequence_begin(buffers)) {
                    auto* data = static_cast<std::byte*>(buffer.data());
                    std::size_t size = buffer.size();
                    const std::size_t available = std::min(
                        size, array_->data_.size()
                                  - gsl::narrow_cast<size_t>(read_offset));

                    std::copy_n(array_->data_.begin()
                                    + gsl::narrow_cast<long>(read_offset),
                                available, data);
                    bytes_transferred += available;
                    read_offset += available;

                    if (available < size) { break; }
                }
                // Update read_pos_ only for stream-oriented reads
                if (offset == 0) { read_pos_ = read_offset; }
            }

            handler(ec, bytes_transferred);
        }

        std::shared_ptr<const impl::Array> array_;
        std::size_t read_pos_ = 0;
    };

    class Array_writer : public Write_stream<Array_writer>,
                         public Random_access_write_device<Array_writer>,
                         public std::enable_shared_from_this<Array_writer> {
    public:
        explicit Array_writer(executor_type executor,
                              std::shared_ptr<Array> array)
            : Write_stream<Array_writer>{std::move(executor)},
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
            boost::asio::post(
                get_executor(),
                [this, self = shared_from_this(), buffers,
                 handler2 = std::forward<Write_handler>(handler)]() mutable {
                    do_write_some(buffers, array_->data_.size(),
                                  std::move(handler2));
                });
        }

        template<typename Const_buffer_sequence, typename Write_handler>
        void async_write_some_at(uint64_t offset,
                                 const Const_buffer_sequence& buffers,
                                 Write_handler&& handler)
        {
            boost::asio::post(
                get_executor(),
                [this, self = shared_from_this(), offset, buffers,
                 handler2 = std::forward<Write_handler>(handler)]() mutable {
                    do_write_some(buffers, offset, std::move(handler2));
                });
        }
    private:
        template<typename Const_buffer_sequence, typename Write_handler>
        void do_write_some(const Const_buffer_sequence& buffers,
                           uint64_t offset, Write_handler&& handler)
        {
            std::size_t bytes_transferred = 0;
            const boost::system::error_code ec;

            for (const auto& buffer: buffers) {
                const auto* data = static_cast<const std::byte*>(buffer.data());
                const std::size_t size = buffer.size();

                if (offset + bytes_transferred + size > array_->data_.size()) {
                    array_->data_.resize(offset + bytes_transferred + size);
                }

                std::copy_n(data, size,
                            array_->data_.begin()
                                + gsl::narrow_cast<long>(offset)
                                + gsl::narrow_cast<long>(bytes_transferred));
                bytes_transferred += size;
            }

            std::forward<Write_handler>(handler)(ec, bytes_transferred);
        }

        std::shared_ptr<Array> array_;
    };
} // namespace impl
namespace factory {
    class LIBHYPHANET_EXPORT Array_factory : public Factory {
    public:
        [[nodiscard]] std::shared_ptr<Random_access>
        make_bucket(size_t /*size*/) const override
        {
            return std::make_shared<impl::Array>();
        }

        [[nodiscard]] boost::asio::awaitable<std::shared_ptr<Random_access>>
        make_immutable_bucket(const executor_type executor,
                              std::vector<std::byte> data, size_t length,
                              size_t offset = 0) const override
        {
            if (data.size() < offset + length) { co_return nullptr; }

            auto bucket
                = std::dynamic_pointer_cast<impl::Array>(make_bucket(length));
            if (!bucket) { co_return nullptr; }

            auto write_stream = get_random_access_writer(executor, bucket);

            co_await boost::asio::async_write_at(*write_stream, offset,
                                                 boost::asio::buffer(data),
                                                 boost::asio::use_awaitable);

            bucket->set_read_only();

            co_return std::move(bucket);
        }
    };
} // namespace factory

} // namespace bucket::random
#endif /* LIBHYPHANET_BUCKET_RANDOM_H */
