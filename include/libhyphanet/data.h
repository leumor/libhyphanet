#ifndef LIBHYPHANET_DATA_H
#define LIBHYPHANET_DATA_H

#include <cstddef>
#include <vector>

namespace data {

namespace block {
    class Storable {
    public:
        virtual ~Storable() = default;

        [[nodiscard]] virtual std::vector<std::byte> get_routing_key() = 0;
        [[nodiscard]] virtual std::vector<std::byte> get_full_key() = 0;
    };

} // namespace block

namespace bucket {}

namespace store {}

} // namespace data

#endif /* LIBHYPHANET_DATA_H */
