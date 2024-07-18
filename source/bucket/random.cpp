#include "libhyphanet/bucket/random.h"
#include <boost/asio/write.hpp>

namespace bucket::random {

boost::asio::awaitable<std::unique_ptr<Random_access>>
Factory::make_immutable_bucket(std::vector<std::byte> data, size_t length,
                               size_t offset) const
{
    if (data.size() < offset + length) { co_return nullptr; }

    auto bucket = make_bucket(length);
    if (!bucket) { co_return nullptr; }

    // co_await boost::asio::async_write()
}

} // namespace bucket::random