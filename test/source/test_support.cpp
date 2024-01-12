#include "libhyphanet/support.h"
#include "libhyphanet/support/base64.h"
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

TEST_CASE("url can be decoded", "[library][support]")
{
    const std::string url{"%41%42%43alot"};

    auto decoded = support::util::url_decode(url, false);

    INFO("decoded url: " << decoded);

    REQUIRE_THAT(decoded, Catch::Matchers::Equals("ABCalot"));
}

TEST_CASE("Freenet specified versions of base64", "[library][support]")
{
    using namespace Catch::Matchers;
    using namespace support::base64;
    using namespace support::util;

    std::vector<std::byte> decoded{
        std::byte{0xFF}, std::byte{0xEE}, std::byte{0xDD}, std::byte{0xCC},
        std::byte{0xBB}, std::byte{0xAA}, std::byte{0x99}, std::byte{0x88},
        std::byte{0x77}, std::byte{0x66}, std::byte{0x55}, std::byte{0x44},
        std::byte{0x33}, std::byte{0x22}, std::byte{0x11}, std::byte{0x00}};

    auto encoded = encode_freenet(decoded);
    REQUIRE_THAT(encoded, Equals("-~7dzLuqmYh3ZlVEMyIRAA"));
    REQUIRE(decode_freenet(encoded) == decoded);

    encoded = encode_standard(decoded);
    REQUIRE_THAT(encoded, Equals("/+7dzLuqmYh3ZlVEMyIRAA=="));
    REQUIRE(decode_standard(encoded) == decoded);

    const std::u8string u8str{u8"Hello, 世界"};
    encoded = encode_str_standard<char8_t>(u8str);
    REQUIRE_THAT(encoded, Equals("SGVsbG8sIOS4lueVjA=="));
    auto decoded_str = decode_str_standard(encoded);
    auto decoded_u8str = str_to_u8str(decoded_str);
    REQUIRE(decoded_u8str == u8str);
}