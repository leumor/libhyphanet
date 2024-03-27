#ifndef LIBHYPHANET_BUCKET_H
#define LIBHYPHANET_BUCKET_H

#include <cstddef>
#include <memory>
#include <ostream>
namespace bucket {

/**
 * @brief A bucket is any arbitrary object can temporarily store data.
 *
 * @details
 * In other words, it is the equivalent of a temporary file, but it could be in
 * RAM, on disk, encrypted, part of a file on disk, composed of a chain of other
 * buckets etc.
 *
 */
class Bucket {
public:
    virtual ~Bucket() = default;

    /**
     * @brief Returns an std::ostream that is used to put data in this Bucket,
     * from the beginning.
     *
     * @details
     * It is not possible to append data to a Bucket! This simplifies
     * the code significantly for some classes. If you need to append, just pass
     * the std::ostream around. Will be buffered if appropriate (e.g. byte array
     * backed buckets don't need to be buffered).
     */
    [[nodiscard]] virtual std::unique_ptr<std::ostream> get_output_stream() = 0;

    /**
     * @brief Get an std::ostream which is not buffered.
     *
     * @details
     * Should be called when we will buffer the stream at a higher level or when
     * we will only be doing large writes (e.g. copying data from one Bucket to
     * another). Does not make any more persistence guarantees than
     * get_output_stream() does, this is just to save memory.
     */
    [[nodiscard]] virtual std::unique_ptr<std::ostream>
    get_output_stream_unbuffered() = 0;

    /**
     * @brief Returns an std::istream that reads data from this Bucket.
     *
     * @details
     * If there is no data in this bucket, nullptr is returned.
     */
    [[nodiscard]] virtual std::unique_ptr<std::istream> get_input_stream() = 0;

    [[nodiscard]] virtual std::unique_ptr<std::istream>
    get_input_stream_unbuffered() = 0;

    /**
     * @brief Returns a name for the bucket.
     *
     * @details
     * It may be used to identify them in certain situations.
     */
    [[nodiscard]] virtual std::string get_name() = 0;

    /**
     * @brief Returns the amount of data currently in this bucket in bytes.
     */
    [[nodiscard]] virtual size_t size() = 0;

    /**
     * @brief Is the bucket read-only?
     */
    [[nodiscard]] virtual bool is_readonly() = 0;

    /**
     * @brief Make the bucket read-only. Irreversible.
     */
    virtual void set_read_only() = 0;

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
    [[nodiscard]] virtual Bucket create_shadow() = 0;
};
} // namespace bucket

#endif /* LIBHYPHANET_BUCKET_H */
