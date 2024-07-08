#ifndef LIBHYPHANET_BUCKET_H
#define LIBHYPHANET_BUCKET_H

#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <cstddef>
#include <gsl/util>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace bucket {

/**
 * @brief A bucket is any arbitrary object can temporarily store data.
 *
 * @details
 * In other words, it is the equivalent of a temporary file, but it could be in
 * RAM, on disk, encrypted, part of a file on disk, composed of a chain of other
 * buckets etc.
 *
 * A bucket also meets the requirrements of Boost Asio's AsyncReadStream and
 * AsyncWriteStream.
 *
 */
class Bucket {
public:
    virtual ~Bucket() = default;

    /**
     * @brief Returns a name for the bucket.
     *
     * @details
     * It may be used to identify them in certain situations.
     */
    [[nodiscard]] virtual std::string get_name() { return name_; }

    /**
     * @brief Returns the amount of data currently in this bucket in bytes.
     */
    [[nodiscard]] virtual size_t size() = 0;

    /**
     * @brief Is the bucket read-only?
     */
    [[nodiscard]] virtual bool is_readonly() { return readonly_; }

    /**
     * @brief Make the bucket read-only. Irreversible.
     */
    virtual void set_read_only() { readonly_ = true; }

    /**
     * @brief Create a shallow read-only copy of this bucket, using different
     * objects but using the same external storage.
     *
     * @details
     * If this is not possible, return null. Note that if the underlying bucket
     * is deleted, the copy will become invalid and probably throw an
     * exception on read, or possibly return too-short data etc. In some use
     * cases e.g. on fproxy, this is acceptable.
     *
     * @return Bucket
     */
    [[nodiscard]] virtual std::unique_ptr<Bucket> create_shadow() = 0;
protected:
    void set_name(std::string_view name) { name_ = name; }
private:
    std::string name_;
    bool readonly_ = false;
};

class Stream {
public:
    explicit Stream(std::shared_ptr<boost::asio::io_context> io_context)
        : io_context_{std::move(io_context)}
    {}

    [[nodiscard]] std::shared_ptr<boost::asio::io_context>
    get_io_context() const
    {
        return io_context_;
    }

    /**
     * @brief Returns the associated I/O executor.
     *
     * @details
     * It's a requirement of AsyncReadStream and AsyncWriteStream.
     *
     * @return boost::asio::io_context::executor_type the associated I/O
     * executor.
     */
    boost::asio::io_context::executor_type get_executor() noexcept
    {
        return (*io_context_).get_executor();
    }
private:
    std::shared_ptr<boost::asio::io_context> io_context_;
};

class Array_read_stream;
class Array_write_stream;

class Array : public Bucket {
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

    [[nodiscard]] size_t size() override { return data_.size(); }
private:
    std::vector<std::byte> data_;
};

class Array_read_stream : public Stream {
public:
    explicit Array_read_stream(
        std::shared_ptr<boost::asio::io_context> io_context,
        std::shared_ptr<const Array> array)
        : Stream{std::move(io_context)}, array_{std::move(array)}
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

        std::copy(array_->data_.begin()
                      + gsl::narrow_cast<long>(read_position_),
                  array_->data_.begin() + gsl::narrow_cast<long>(read_position_)
                      + bytes_to_read,
                  static_cast<std::byte*>(buffers.data()));

        read_position_ += bytes_to_read;

        // Schedule the completion handler
        boost::asio::post(get_io_context(),
                          [handler_fwd = std::forward<Read_handler>(handler),
                           bytes_to_read]() mutable {
                              handler_fwd(boost::system::error_code{},
                                          bytes_to_read);
                          });
    }
private:
    std::shared_ptr<const Array> array_;
    std::size_t read_position_ = 0;
};

class Array_write_stream : public Stream {
public:
    explicit Array_write_stream(
        std::shared_ptr<boost::asio::io_context> io_context,
        std::shared_ptr<Array> array)
        : Stream{std::move(io_context)}, array_{std::move(array)}
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
        for (const auto& buffer: boost::asio::buffer_sequence_begin(buffers),
             boost::asio::buffer_sequence_end(buffers)) {
            const auto begin = static_cast<const std::byte*>(buffer.data());
            const std::byte* end = begin + buffer.size();
            array_->data_.insert(array_->data_.end(), begin, end);
            bytes_transferred += buffer.size();
        }

        boost::asio::post(get_io_context(),
                          [handler_fwd = std::forward<Write_handler>(handler),
                           bytes_transferred]() mutable {
                              handler_fwd(boost::system::error_code(),
                                          bytes_transferred);
                          });
    }
private:
    std::shared_ptr<Array> array_;
};
} // namespace bucket

#endif /* LIBHYPHANET_BUCKET_H */
