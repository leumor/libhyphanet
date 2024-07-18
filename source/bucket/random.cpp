#include "libhyphanet/bucket/random.h"

namespace bucket::random {

std::unique_ptr<Random_access>
Factory::make_immutable_bucket(std::vector<std::byte> data, size_t offset,
                               size_t length) const
{
    auto bucket = make_bucket(length);
    if (!bucket) { return nullptr; }
}

} // namespace bucket::random