#ifndef LIBHYPHANET_BUCKET_H
#define LIBHYPHANET_BUCKET_H

#include <boost/asio.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <cstddef>
#include <gsl/util>
#include <libhyphanet/libhyphanet_export.h>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace bucket {

class Reader_writer {
public:
    using executor_type = boost::asio::any_io_executor;

    virtual ~Reader_writer() = default;

    explicit Reader_writer(executor_type executor)
        : executor_{std::move(executor)}
    {}

    [[nodiscard]] virtual executor_type get_executor() const noexcept
    {
        return executor_;
    }
private:
    executor_type executor_;
};

template<typename Derived> class Read_stream : public Reader_writer {
public:
    using Reader_writer::Reader_writer;

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
        static_cast<Derived*>(this)->async_read_some(
            buffers, std::forward<Read_handler>(handler));
    }
};

template<typename Derived> class Write_stream : public Reader_writer {
public:
    using Reader_writer::Reader_writer;

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
        static_cast<Derived*>(this)->async_write_some(
            buffers, std::forward<Write_handler>(handler));
    }
};

class LIBHYPHANET_EXPORT Bucket {
public:
    virtual ~Bucket() = default;

    /**
     * @brief Returns a name for the bucket.
     *
     * @details
     * It may be used to identify them in certain situations.
     */
    [[nodiscard]] virtual std::string get_name() const = 0;

    /**
     * @brief Returns the amount of data currently in this bucket in bytes.
     */
    [[nodiscard]] virtual size_t size() const = 0;

    /**
     * @brief Is the bucket read-only?
     */
    [[nodiscard]] virtual bool is_readonly() const = 0;

    /**
     * @brief Make the bucket read-only. Irreversible.
     */
    virtual void set_read_only() = 0;

    /**
     * @brief Create a shallow read-only copy of this bucket, using
     * different objects but using the same external storage.
     *
     * @details
     * If this is not possible, return nullptr. Note that if the underlying
     * bucket is deleted, the copy will become invalid and probably throw an
     * exception on read, or possibly return too-short data etc. In some use
     * cases e.g. on fproxy, this is acceptable.
     *
     * @return std::unique_ptr<Bucket> A shadow copy of this bucket. nullptr if
     * it's not possible to create one.
     */
    [[nodiscard]] virtual std::unique_ptr<Bucket> create_shadow() = 0;
};

using executor_type = boost::asio::any_io_executor;

template<typename T> concept DerivedFromBucket = std::derived_from<T, Bucket>;

template<DerivedFromBucket T>
[[nodiscard]] std::unique_ptr<Read_stream<typename T::reader_type>>
get_read_stream(const executor_type& executor, const std::shared_ptr<T> bucket)
{
    return std::make_unique<T::reader_type>(executor, bucket);
}

template<DerivedFromBucket T>
[[nodiscard]] std::unique_ptr<Write_stream<typename T::writer_type>>
get_write_stream(const executor_type& executor, const std::shared_ptr<T> bucket)
{
    return std::make_unique<T::writer_type>(executor, bucket);
}

namespace impl {
    /**
     * @brief A bucket is any arbitrary object can temporarily store data.
     *
     * @details
     * In other words, it is the equivalent of a temporary file, but it
     * could be in RAM, on disk, encrypted, part of a file on disk, composed
     * of a chain of other buckets etc.
     *
     * A bucket also meets the requirements of Boost Asio's AsyncReadStream
     * and AsyncWriteStream.
     *
     */
    class Bucket : public virtual bucket::Bucket {
    public:
        /**
         * @brief Returns a name for the bucket.
         *
         * @details
         * It may be used to identify them in certain situations.
         */
        [[nodiscard]] std::string get_name() const override { return name_; }

        /**
         * @brief Is the bucket read-only?
         */
        [[nodiscard]] bool is_readonly() const override { return readonly_; }

        /**
         * @brief Make the bucket read-only. Irreversible.
         */
        void set_read_only() override { readonly_ = true; }
    protected:
        void set_name(std::string_view name) { name_ = name; }
    private:
        std::string name_;
        bool readonly_ = false;
    };

} // namespace impl
} // namespace bucket

#endif /* LIBHYPHANET_BUCKET_H */
