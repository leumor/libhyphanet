#include "libhyphanet/keys.h"
#include "libhyphanet/keys/user.h"
#include <catch2/catch_test_macros.hpp>
#include <fmt/core.h>
#include <string>
#include <vector>

TEST_CASE("freenet keys are functional", "[library][keys]")
{
    static const std::string wanna_usk_1
        = "USK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
          "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search/17/index_d51.xml";
    static const std::string wanna_ssk_1
        = "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
          "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17/index_d51.xml";
    static const std::string wanna_chk_1
        = "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-"
          "ZihSskPYDTY19uhrMwqDV-~Sk,AAMC--8/index_d51.xml";
    static const std::string ksk_example = "KSK@gpl.txt";

    SECTION("broken keys")
    {
        // Broken USK
        auto uri = keys::Uri::create("USK@/broken/0");
        REQUIRE_THROWS_AS(keys::user::Key::create(*uri),
                          keys::exception::Malformed_uri);

        // Broken SSK
        uri = keys::Uri::create("SSK@/broken-0");
        REQUIRE_THROWS_AS(keys::user::Key::create(*uri),
                          keys::exception::Malformed_uri);
    }

    SECTION("added valid schema prefixes are ignored")
    {
        for (const auto& prefix: std::vector<std::string>{
                 "freenet", "web+freenet", "ext+freenet", "hypha", "hyphanet",
                 "web+hypha", "web+hyphanet", "ext+hypha", "ext+hyphanet"}) {
            auto uri
                = keys::Uri::create(fmt::format("{}:{}", prefix, wanna_usk_1));
            REQUIRE(uri->to_string() == wanna_usk_1);
            auto key = keys::user::Key::create(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_usk_1);

            uri = keys::Uri::create(fmt::format("{}:{}", prefix, wanna_ssk_1));
            REQUIRE(uri->to_string() == wanna_ssk_1);
            key = keys::user::Key::create(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_ssk_1);

            uri = keys::Uri::create(fmt::format("{}:{}", prefix, wanna_chk_1));
            REQUIRE(uri->to_string() == wanna_chk_1);
            key = keys::user::Key::create(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_chk_1);

            uri = keys::Uri::create(fmt::format("{}:{}", prefix, ksk_example));
            REQUIRE(uri->to_string() == ksk_example);
            key = keys::user::Key::create(*uri);
            REQUIRE(key->to_uri().to_string() == ksk_example);
        }
    }
}