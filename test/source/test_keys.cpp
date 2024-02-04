#include "libhyphanet/keys.h"
#include "libhyphanet/keys/user.h"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("freenet keys are functional", "[library][keys]")
{
    SECTION("broken keys")
    {
        const auto uri = keys::Uri::create("USK@/broken/0");

        REQUIRE_THROWS_AS(keys::user::Key::create(*uri),
                          keys::exception::Malformed_uri);
    }
}