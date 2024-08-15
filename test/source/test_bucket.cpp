#include "libhyphanet/bucket.h"
#include "libhyphanet/bucket/random.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/impl/co_spawn.hpp>
#include <boost/asio/impl/read.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <fmt/core.h>
#include <fmt/format.h>
#include <memory>
#include <vector>

boost::asio::awaitable<void> perform_io(boost::asio::any_io_executor executor)
{
    bucket::random::factory::Array_factory factory;
    auto data = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}
    };
    auto bucket = co_await factory.make_immutable_bucket(executor, data, 10, 1);

    std::vector<std::byte> buffer(10);
    auto bytes_read = co_await boost::asio::async_read(
        *bucket, boost::asio::buffer(buffer), boost::asio::use_awaitable
    );

    fmt::println("{} bytes read", bytes_read);
    fmt::println("buffer: {:02x}", fmt::join(buffer, " "));

    REQUIRE(bytes_read == 5);
    REQUIRE(buffer
            == std::vector<std::byte>{
                std::byte{0x00},
                std::byte{0x01},
                std::byte{0x02},
                std::byte{0x03},
                std::byte{0x04},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
            });
}

TEST_CASE("freenet buckets are functional", "[library][bucket]") // NOLINT
{
    boost::asio::io_context io_context;
    boost::asio::co_spawn(
        io_context, perform_io(io_context.get_executor()), boost::asio::detached
    );

    io_context.run();
}
