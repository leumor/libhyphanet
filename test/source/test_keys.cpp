#include "libhyphanet/key.h"
#include "libhyphanet/key/user.h"

#include <catch2/catch_test_macros.hpp>
#include <fmt/core.h>
#include <fmt/format.h>
#include <memory>
#include <string>
#include <vector>

TEST_CASE("freenet keys are functional", "[library][keys]") // NOLINT
{
    static const std::string wanna_usk_1 =
        "USK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
        "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search/17/index_d51.xml";
    static const std::string wanna_ssk_1 =
        "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
        "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17/index_d51.xml";
    static const std::string wanna_chk_1 =
        "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-"
        "ZihSskPYDTY19uhrMwqDV-~Sk,AAMC--8/index_d51.xml";
    static const std::string ksk_example = "KSK@gpl.txt";

    SECTION("ssk/usk conversion")
    {
        using namespace key;

        auto uri_usk = Uri::create(wanna_usk_1);
        auto usk = user::create<user::Usk>(*uri_usk);
        auto uri_ssk = Uri::create(wanna_ssk_1);
        auto ssk = user::create<user::Ssk>(*uri_ssk);

        REQUIRE(wanna_ssk_1 == user::to_ssk(*usk)->to_uri().to_string());

        auto usk_2 = user::to_usk(*ssk);
        REQUIRE(usk_2 != nullptr);
        REQUIRE(wanna_usk_1 == usk_2->to_uri().to_string()); // NOLINT

        uri_ssk = Uri::create(
            "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
            "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17XXXX/index_d51.xml"
        );
        ssk = user::create<user::Ssk>(*uri_ssk);
        REQUIRE_NOTHROW(user::to_usk(*ssk));

        uri_ssk = Uri::create(
            "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-"
            "WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search17/index_d51.xml"
        );
        ssk = user::create<user::Ssk>(*uri_ssk);
        REQUIRE(user::to_usk(*ssk) == nullptr);
    }

    SECTION("broken keys")
    {
        // Broken USK
        auto uri = key::Uri::create("USK@/broken/0");
        REQUIRE_THROWS_AS(
            key::user::create_key(*uri), key::exception::Malformed_uri
        );

        // Broken SSK
        uri = key::Uri::create("SSK@/broken-0");
        REQUIRE_THROWS_AS(
            key::user::create_key(*uri), key::exception::Malformed_uri
        );
    }

    SECTION("added valid schema prefixes are ignored")
    {
        using namespace key::user;

        for (const auto& prefix: std::vector<std::string>{
                 "freenet",
                 "web+freenet",
                 "ext+freenet",
                 "hypha",
                 "hyphanet",
                 "web+hypha",
                 "web+hyphanet",
                 "ext+hypha",
                 "ext+hyphanet"
             }) {
            auto uri =
                key::Uri::create(fmt::format("{}:{}", prefix, wanna_usk_1));
            REQUIRE(uri->to_string() == wanna_usk_1);
            auto key = key::user::create_key(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_usk_1);
            REQUIRE(key->is<Usk>());
            REQUIRE(!key->is<Ksk>());

            if (auto usk = key->as<Usk>(); usk != nullptr) {
                REQUIRE(usk->get_suggested_edition() == 17);
            }
            else {
                REQUIRE(false);
            }

            uri = key::Uri::create(fmt::format("{}:{}", prefix, wanna_ssk_1));
            REQUIRE(uri->to_string() == wanna_ssk_1);
            key = key::user::create_key(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_ssk_1);

            uri = key::Uri::create(fmt::format("{}:{}", prefix, wanna_chk_1));
            REQUIRE(uri->to_string() == wanna_chk_1);
            key = key::user::create_key(*uri);
            REQUIRE(key->to_uri().to_string() == wanna_chk_1);

            uri = key::Uri::create(fmt::format("{}:{}", prefix, ksk_example));
            REQUIRE(uri->to_string() == ksk_example);
            key = key::user::create_key(*uri);
            REQUIRE(key->to_uri().to_string() == ksk_example);
        }
    }
}

TEST_CASE("derive request uri", "[library][keys]")
{
    using namespace key;

    auto chk_uri =
        "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-"
        "ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
    auto chk = user::create_key(*Uri::create(chk_uri));
    REQUIRE(chk->to_request_uri().to_string() == chk_uri);

    auto ksk_uri = "KSK@test";
    auto ksk = user::create_key(*Uri::create(ksk_uri));
    REQUIRE(ksk->to_request_uri().to_string() == ksk_uri);

    auto request_uri_usk =
        "USK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,"
        "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/WebOfTrust/5";
    auto request_usk = user::create_key(*Uri::create(request_uri_usk));
    auto insert_uri_usk =
        "USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
        "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/WebOfTrust/5";
    auto insert_usk = user::create_key(*Uri::create(insert_uri_usk));
    REQUIRE(insert_usk->to_request_uri().to_string() == request_uri_usk);
    // Request uri's request uri is itself
    REQUIRE(request_usk->to_request_uri().to_string() == request_uri_usk);

    auto request_uri_ssk =
        "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,"
        "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/WebOfTrust-5";
    auto request_ssk = user::create_key(*Uri::create(request_uri_ssk));
    auto insert_uri_ssk =
        "SSK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
        "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/WebOfTrust-5";
    auto insert_ssk = user::create_key(*Uri::create(insert_uri_ssk));
    REQUIRE(insert_ssk->to_request_uri().to_string() == request_uri_ssk);
    // Request uri's request uri is itself
    REQUIRE(request_ssk->to_request_uri().to_string() == request_uri_ssk);

    request_uri_ssk = "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,"
                      "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/";
    request_ssk = user::create_key(*Uri::create(request_uri_ssk));
    insert_uri_ssk = "SSK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
                     "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/";
    insert_ssk = user::create_key(*Uri::create(insert_uri_ssk));
    REQUIRE(insert_ssk->to_request_uri().to_string() == request_uri_ssk);
    // Request uri's request uri is itself
    REQUIRE(request_ssk->to_request_uri().to_string() == request_uri_ssk);
}
