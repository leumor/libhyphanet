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

namespace concepts {

    template<typename T>
    concept Has_Get_Executor = requires(const T t) {
        { t.get_executor() } noexcept -> std::same_as<executor_type>;
    };

    /**
     * @brief Returns a name for the bucket.
     *
     * @details
     * It may be used to identify them in certain situations.
     */
    template<typename T>
    concept Has_Get_Name = requires(const T t) {
        { t.get_name() } -> std::same_as<std::string>;
    };

    /**
     * @brief Returns the amount of data currently in this bucket in bytes.
     */
    template<typename T>
    concept Has_Size = requires(const T t) {
        { t.size() } -> std::same_as<size_t>;
    };

    /**
     * @brief Is the bucket read-only?
     */
    template<typename T>
    concept Has_Is_Readonly = requires(const T t) {
        { t.is_readonly() } -> std::same_as<bool>;
    };

    /**
     * @brief Make the bucket read-only. Irreversible.
     */
    template<typename T>
    concept Has_Set_Read_Only = requires(T t) {
        { t.set_read_only() } -> std::same_as<void>;
    };

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
    template<typename T>
    concept Has_Create_Shadow = requires(T t) {
        { t.create_shadow() } -> std::same_as<std::unique_ptr<T>>;
    };

    template<typename T>
    concept Bucket =
        Has_Get_Executor<T> && Has_Get_Name<T> && Has_Size<T>
        && Has_Is_Readonly<T> && Has_Set_Read_Only<T> && Has_Create_Shadow<T>;
} // namespace concepts

class LIBHYPHANET_EXPORT Reader_writer {
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
class Bucket : public Reader_writer {
public:
    using Reader_writer::Reader_writer;

    /**
     * @brief Returns a name for the bucket.
     *
     * @details
     * It may be used to identify them in certain situations.
     */
    [[nodiscard]] virtual std::string get_name() const { return name_; }

    /**
     * @brief Is the bucket read-only?
     */
    [[nodiscard]] virtual bool is_readonly() const { return readonly_; }

    /**
     * @brief Make the bucket read-only. Irreversible.
     */
    void virtual set_read_only() { readonly_ = true; }

protected:
    void set_name(std::string_view name) { name_ = name; }

private:
    std::string name_;
    bool readonly_ = false;
};

} // namespace bucket

#endif /* LIBHYPHANET_BUCKET_H */
