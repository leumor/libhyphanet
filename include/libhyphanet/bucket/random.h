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

template<typename T, typename Mutable_buffer_sequence, typename Read_handler>
concept Has_Method_Async_Read_Some_At = requires(
    T t, uint64_t offset, const Mutable_buffer_sequence& buffers,
    Read_handler&& handler) {
    {
        t.template async_read_some_at<Mutable_buffer_sequence, Read_handler>(
            offset, buffers, handler)
    } -> std::same_as<void>;
};
template<typename Derived>
class LIBHYPHANET_EXPORT Random_access_read_device {
public:
    using executor_type = boost::asio::any_io_executor;

    template<typename Mutable_buffer_sequence, typename Read_handler>
    void async_read_some_at(uint64_t offset,
                            const Mutable_buffer_sequence& buffers,
                            Read_handler&& handler)
    {
        static_assert(
            Has_Method_Async_Read_Some_At<Derived, Mutable_buffer_sequence,
                                          Read_handler>,
            "Derived class must implement async_read_some_at()");
        static_cast<Derived*>(this)->async_read_some_at(
            offset, buffers, std::forward<Read_handler>(handler));
    }
};

template<typename T, typename Const_buffer_sequence, typename Write_handler>
concept Has_Method_Async_Write_Some_At = requires(
    T t, uint64_t offset, const Const_buffer_sequence& buffers,
    Write_handler&& handler) {
    {
        t.template async_write_some_at<Const_buffer_sequence, Write_handler>(
            offset, buffers, handler)
    } -> std::same_as<void>;
};
template<typename Derived>
class LIBHYPHANET_EXPORT Random_access_write_device {
public:
    using executor_type = boost::asio::any_io_executor;

    template<typename Const_buffer_sequence, typename Write_handler>
    void async_write_some_at(uint64_t offset,
                             const Const_buffer_sequence& buffers,
                             Write_handler&& handler)
    {
        static_assert(
            Has_Method_Async_Write_Some_At<Derived, Const_buffer_sequence,
                                           Write_handler>,
            "Derived class must implement async_write_some()");
        static_cast<Derived*>(this)->async_write_some_at(
            offset, buffers, std::forward<Write_handler>(handler));
    }
};

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
template<typename Derived>
class LIBHYPHANET_EXPORT Random_access
    : public virtual Bucket<Random_access<Derived>>,
      public Random_access_read_device<Derived>,
      public Random_access_write_device<Derived> {
public:
    // TODO: toRandomAccessBuffer()
};
template<typename T>
concept Derived_From_Random_Access = std::derived_from<T, Random_access<T>>;

class LIBHYPHANET_EXPORT Array : public virtual Random_access<Array> {};

template<typename Factory, typename T>
concept Has_Method_Make_Bucket
    = requires(Factory factory, T t, executor_type executor, size_t size) {
          {
              factory.template make_bucket<T>(executor, size)
          } -> std::same_as<std::shared_ptr<T>>;
      } && Derived_From_Random_Access<T>;
template<typename Factory, typename T>
concept Has_Method_Make_Imutable_Bucket = requires(Factory factory, T t,
                                                   executor_type executor,
                                                   const std::vector<std::byte>&
                                                       data,
                                                   size_t length,
                                                   size_t offset) {
    {
        factory.template make_immutable_bucket<T>(data, length, offset)
    } -> std::same_as<boost::asio::awaitable<std::shared_ptr<T>>>;
} && Derived_From_Random_Access<T>;
template<typename Derived>
class LIBHYPHANET_EXPORT Factory {
public:
    virtual ~Factory() = default;

    /**
     * @brief Create a bucket.
     *
     * @param size The maximum size of the data, or -1 if we don't know.
     * Some buckets will throw IOException if you go over this length.
     *
     * @return std::unique_ptr<Random_access> a Random Access Bucket
     */
    template<Derived_From_Random_Access T>
    [[nodiscard]] std::shared_ptr<T> make_bucket(executor_type executor,
                                                 size_t size) const
    {
        static_assert(Has_Method_Make_Bucket<Derived, T>,
                      "Derived factory must implement make_bucket()");
        return static_cast<Derived*>(this)->make_bucket(executor, size);
    }

    template<Derived_From_Random_Access T>
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<T>>
    make_immutable_bucket(executor_type executor, std::vector<std::byte> data,
                          size_t length, size_t offset = 0) const
    {
        static_assert(Has_Method_Make_Imutable_Bucket<Derived, T>,
                      "Derived factory must implement make_immutable_bucket()");
        return static_cast<Derived*>(this)->make_immutable_bucket(
            executor, data, length, offset);
    }
};

namespace impl {

    template<typename Derived>
    class Random_access
        : public virtual bucket::random::Random_access<Derived>,
          public bucket::impl::Bucket<bucket::random::Random_access<Derived>> {
    public:
        explicit Random_access(const executor_type& executor)
            : bucket::impl::Bucket<bucket::random::Random_access<Derived>>{
                  executor}
        {}
    };

    class Array_reader;
    class Array_writer;

    class Array : public virtual bucket::random::Array,
                  public Random_access<bucket::random::Array>,
                  public std::enable_shared_from_this<Array> {
    public:
        using executor_type = boost::asio::any_io_executor;

        Array(const executor_type& executor,
              const std::vector<std::byte>& init_data = {},
              std::string_view name = "ArrayBucket")
            : Random_access{executor}, data_{init_data}
        {
            set_name(name);
        }

        [[nodiscard]] size_t size() const override { return data_.size(); }

        [[nodiscard]] std::unique_ptr<Array> create_shadow() { return nullptr; }

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
            auto self = shared_from_this();
            boost::asio::post(
                get_executor(),
                [this, self, buffers,
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
                    do_write_some(buffers, data_.size(), std::move(handler2));
                });
        }

        template<typename Const_buffer_sequence, typename Write_handler>
        // cppcheck-suppress duplInheritedMember
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
        template<typename Mutable_buffer_sequence, typename Read_handler>
        void do_read_some(const Mutable_buffer_sequence& buffers,
                          uint64_t offset, Read_handler handler)
        {
            std::size_t bytes_transferred = 0;
            boost::system::error_code ec;

            // Use read_pos_ for stream-oriented reads, offset for random access
            // reads
            if (uint64_t read_offset = (offset == 0) ? read_pos_ : offset;
                read_offset > data_.size()) {
                ec = boost::asio::error::eof;
            }
            else {
                for (const auto& buffer: buffers) {
                    auto* data = static_cast<std::byte*>(buffer.data());
                    const std::size_t size = buffer.size();
                    const std::size_t available = std::min(
                        size,
                        data_.size() - gsl::narrow_cast<size_t>(read_offset));

                    std::copy_n(data_.begin()
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

        template<typename Const_buffer_sequence, typename Write_handler>
        void do_write_some(const Const_buffer_sequence& buffers,
                           uint64_t offset, Write_handler&& handler)
        {
            std::size_t bytes_transferred = 0;
            const boost::system::error_code ec;

            for (const auto& buffer: buffers) {
                const auto* data = static_cast<const std::byte*>(buffer.data());
                const std::size_t size = buffer.size();

                if (offset + bytes_transferred + size > data_.size()) {
                    data_.resize(offset + bytes_transferred + size);
                }

                std::copy_n(data, size,
                            data_.begin() + gsl::narrow_cast<long>(offset)
                                + gsl::narrow_cast<long>(bytes_transferred));
                bytes_transferred += size;
            }

            std::forward<Write_handler>(handler)(ec, bytes_transferred);
        }

        std::vector<std::byte> data_;
        std::size_t read_pos_ = 0;
    };

} // namespace impl
namespace factory {
    class LIBHYPHANET_EXPORT Array_factory : public Factory<Array_factory> {
    public:
        [[nodiscard]] std::shared_ptr<impl::Array>
        // cppcheck-suppress duplInheritedMember
        make_bucket(executor_type executor, size_t /*size*/) const
        {
            return std::make_shared<impl::Array>(executor);
        }

        [[nodiscard]] boost::asio::awaitable<std::shared_ptr<impl::Array>>
        // cppcheck-suppress duplInheritedMember
        make_immutable_bucket(executor_type executor,
                              std::vector<std::byte> data, size_t length,
                              size_t offset = 0) const
        {
            Expects(data.size() + offset <= length);

            auto bucket = make_bucket(executor, length);
            if (!bucket) { co_return nullptr; }

            co_await boost::asio::async_write_at(*bucket, offset,
                                                 boost::asio::buffer(data),
                                                 boost::asio::use_awaitable);

            bucket->set_read_only();

            co_return std::move(bucket);
        }
    };
} // namespace factory

} // namespace bucket::random
#endif /* LIBHYPHANET_BUCKET_RANDOM_H */
