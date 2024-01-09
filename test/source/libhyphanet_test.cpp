#include "libhyphanet/support.h"
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <string>

TEST_CASE("url can be decoded", "[library][support]")
{
    const std::string url{"%41%42%43alot"};

    auto decoded = support::util::url_decode(url, false);

    INFO("decoded url: " << decoded);

    REQUIRE_THAT(decoded, Catch::Matchers::Equals("ABCalot"));
}
