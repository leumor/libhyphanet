#include "libhyphanet/bucket/random.h"
#include "libhyphanet/bucket.h"
#include <boost/asio/write.hpp>
#include <boost/asio/write_at.hpp>

namespace bucket::random {

boost::asio::awaitable<std::unique_ptr<Random_access>>
Factory::make_immutable_bucket(std::vector<std::byte> data, size_t length,
                               size_t offset) const
{
    if (data.size() < offset + length) { co_return nullptr; }

    auto bucket = make_bucket(length);
    if (!bucket) { co_return nullptr; }

    co_await boost::asio::async_write_at(
        *bucket, offset, boost::asio::buffer(data), boost::asio::use_awaitable);

    bucket->set_read_only();

    co_return std::move(bucket);
}

namespace impl {
    std::unique_ptr<Stream>
    Array::get_read_stream(const executor_type& executor) const
    {
        return std::make_unique<Array_read_stream>(executor,
                                                   shared_from_this());
    }

    std::unique_ptr<Stream>
    Array::get_write_stream(const executor_type& executor)
    {
        return std::make_unique<Array_write_stream>(executor,
                                                    shared_from_this());
    }
} // namespace impl

} // namespace bucket::random