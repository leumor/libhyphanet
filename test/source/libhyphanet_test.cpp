#include "libhyphanet/libhyphanet.h"
#include <catch2/catch_test_macros.hpp>
#include <string>

TEST_CASE("Name is libhyphanet", "[library]")
{
    auto const exported = exported_class{};
    REQUIRE(std::string("libhyphanet") == exported.name());
}
