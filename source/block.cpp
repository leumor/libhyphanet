#include "libhyphanet/block.h"

namespace block {
namespace node {
    // =========================================================================
    // Key
    // =========================================================================

    // =========================================================================
    // Chk
    // =========================================================================
    std::vector<std::byte> Chk::get_node_routing_key()
    {
        return get_node_key()->get_node_routing_key();
    }
} // namespace node
} // namespace block