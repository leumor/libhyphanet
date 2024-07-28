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
using executor_type = boost::asio::any_io_executor;

template<typename T, typename Mutable_buffer_sequence, typename Read_handler>
concept HasMethodAsyncReadSome = requires(
    T t, const Mutable_buffer_sequence& buffers, Read_handler&& handler) {
    {
        t.template async_read_some<Mutable_buffer_sequence, Read_handler>(
            buffers, handler)
    } -> std::same_as<void>;
};
template<typename Derived> class Read_stream {
public:
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
        static_assert(HasMethodAsyncReadSome<Derived, Mutable_buffer_sequence,
                                             Read_handler>,
                      "Derived class must implement async_read_some()");
        static_cast<Derived*>(this)->async_read_some(
            buffers, std::forward<Read_handler>(handler));
    }
};

template<typename T, typename Const_buffer_sequence, typename Write_handler>
concept HasMethodAsyncWriteSome = requires(
    T t, const Const_buffer_sequence& buffers, Write_handler&& handler) {
    {
        t.template async_write_some<Const_buffer_sequence, Write_handler>(
            buffers, handler)
    } -> std::same_as<void>;
};
template<typename Derived> class Write_stream {
public:
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
        static_assert(HasMethodAsyncWriteSome<Derived, Const_buffer_sequence,
                                              Write_handler>,
                      "Derived class must implement async_write_some()");
        static_cast<Derived*>(this)->async_write_some(
            buffers, std::forward<Write_handler>(handler));
    }
};

template<typename T, typename Bucket> concept HasMethodCreateShadow
    = requires(T t) {
          { t.create_shadow() } -> std::same_as<std::unique_ptr<T>>;
      } && std::is_base_of_v<Bucket, T>;
template<typename Derived> class LIBHYPHANET_EXPORT Bucket
    : public Read_stream<Derived>,
      public Write_stream<Derived> {
public:
    // explicit Bucket(const executor_type& executor)
    //     : bucket::Reader_writer{executor}
    // {
    // Static assertion to ensure correct CRTP usage
    // static_assert(support::concepts::DerivedFromBase<Derived,
    // Bucket<Derived>>,
    //               "Derived class must inherit from Bucket<Derived>");
    // }

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
    [[nodiscard]] std::unique_ptr<Bucket<Derived>> create_shadow()
    {
        static_assert(HasMethodCreateShadow<Derived, Bucket<Derived>>,
                      "Derived class must implement create_shadow()");

        auto ptr = static_cast<Derived*>(this)->create_shadow();

        return std::move(ptr);
    }
};

namespace impl {

    class Reader_writer {
    public:
        virtual ~Reader_writer() = default;

        explicit Reader_writer(const executor_type& executor)
            : executor_{executor}
        {}

        [[nodiscard]] virtual executor_type get_executor() const noexcept
        {
            return executor_;
        }
    private:
        boost::asio::strand<executor_type> executor_;
    };

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
    template<typename Derived> class Bucket
        : public virtual bucket::Bucket<Derived>,
          public Reader_writer {
    public:
        explicit Bucket(const executor_type& executor): Reader_writer{executor}
        {}

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
