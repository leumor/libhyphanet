#include "libhyphanet/bucket.h"
#include "libhyphanet/bucket/random.h"
#include <catch2/catch_test_macros.hpp>
#include <fmt/core.h>

TEST_CASE("freenet buckets are functional", "[library][bucket]") // NOLINT
{
    boost::asio::io_context io_context;
    bucket::random::factory::Array_factory factory;
    auto data
        = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    auto bucket
        = factory.make_immutable_bucket(io_context.get_executor(), data, 10, 1);
}