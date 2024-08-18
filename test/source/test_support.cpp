#include "libhyphanet/support.h"
#include "libhyphanet/support/base64.h"
#include "test/utf_util.h"

#include <bit>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <cstddef>
#include <fmt/base.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <string>
#include <string_view>
#include <unicode/unistr.h>
#include <vector>

bool are_correctly_encoded_decoded(
    const std::vector<std::string_view>& to_encode, bool ascii
)
{
    using namespace support::url;

    std::vector<std::string> encoded;

    // encoding
    encoded.reserve(to_encode.size());
    for (auto& str: to_encode) {
        auto coded = url_encode(str, ascii);
        encoded.push_back(coded);
    }
    // decoding
    for (size_t i = 0; i < to_encode.size(); ++i) {
        auto orig = to_encode[i];
        auto const& coded = encoded[i];
        auto decoded = url_decode(coded, ascii);

        if (orig != decoded) {
            for (size_t j = 0; j < orig.size(); ++j) {
                auto orig_char = orig.at(j);
                auto decoded_char = decoded.at(j);
                if (j > decoded.size() || orig_char != decoded_char) {
                    fmt::println(
                        "orig: %{:02x}, decoded: %{:02x}",
                        std::bit_cast<unsigned char>(orig_char),
                        std::bit_cast<unsigned char>(decoded_char)
                    );
                    return false;
                }
            }
            return false;
        }
    }

    return true;
}

TEST_CASE("url can be encoded and decoded", "[library][support]") // NOLINT
{
    SECTION("simple decoding")
    {
        const std::string url{"%41%42%43alot"};

        auto decoded = support::url::url_decode(url, false);

        INFO("decoded url: " << decoded);

        REQUIRE_THAT(decoded, Catch::Matchers::Equals("ABCalot"));
    }

    SECTION("encodes a string of ALL unicode characters except the 0-character "
            "and tests whether it is decoded correctly")
    {
        using namespace utf_util;
        auto all_chars_except_null =
            icu::UnicodeString(all_characters.data(), all_characters.size());

        all_chars_except_null.findAndReplace(
            icu::UnicodeString{u'\u0000'}, icu::UnicodeString{}
        );

        std::string all_chars_except_null_utf8;
        all_chars_except_null.toUTF8String(all_chars_except_null_utf8);

        REQUIRE(are_correctly_encoded_decoded(
            std::vector<std::string_view>{all_chars_except_null_utf8}, false
        ));
        REQUIRE(are_correctly_encoded_decoded(
            std::vector<std::string_view>{all_chars_except_null_utf8}, true
        ));
    }

    SECTION("test if encoding and decoding work correctly together with both "
            "safe and unsafe ascii chars")
    {
        using namespace utf_util;

        auto printable_ascii_str_utf8 = uchar_arr_to_str(printable_ascii);

        const std::vector<std::string_view> to_encode = {
            // safe chars
            support::url::safe_url_characters,
            printable_ascii_str_utf8,
            // triple % char, if badly encoded it will generate an exception
            "%%%",
            // no chars
            "",
        };

        REQUIRE(are_correctly_encoded_decoded(to_encode, true));
        REQUIRE(are_correctly_encoded_decoded(to_encode, false));
    }

    SECTION("test if encoding and decoding work correctly together with both "
            "safe and not safe \"advanced\" (non-ascii) chars")
    {
        using namespace utf_util;

        auto stressed_utf_str_utf8 = uchar_arr_to_str(stressed_utf);

        const std::vector<std::string_view> to_encode = {stressed_utf_str_utf8};

        REQUIRE(are_correctly_encoded_decoded(to_encode, true));
        REQUIRE(are_correctly_encoded_decoded(to_encode, false));
    }

    SECTION(
        "test if the force parameter is well-managed for each safe url chars"
    )
    {
        using namespace support::url;

        for (auto& c: safe_url_characters) {
            const std::string to_encode{c};
            std::string expected_result =
                fmt::format("%{:02x}", std::bit_cast<unsigned char>(c));

            REQUIRE(url_encode(to_encode, true, to_encode) == expected_result);
            REQUIRE(url_encode(to_encode, false, to_encode) == expected_result);
        }
    }

    SECTION("test decoding invalid encoded string")
    {
        using namespace support::url;

        // Wrong string
        std::string to_decode{"%00"};

        REQUIRE_THROWS_AS(url_decode(to_decode, false), Url_decode_error);

        // Invalid hex
        to_decode = "123456789abcde"
                  + utf_util::uchar_arr_to_str(utf_util::printable_ascii)
                  + utf_util::uchar_arr_to_str(utf_util::stressed_utf);

        for (size_t i = 0; i < to_decode.size(); ++i) {
            REQUIRE_THROWS_AS(
                url_decode("%" + to_decode.substr(i, 1), false),
                Url_decode_error
            );
        }

        // Tolerant decoding
        to_decode = "%%%";

        REQUIRE_NOTHROW(url_decode(to_decode, true));
    }
}

TEST_CASE("Freenet specified versions of base64", "[library][support]")
{
    using namespace Catch::Matchers;
    using namespace support::base64;
    using namespace support::util;

    std::vector<std::byte> decoded{
        std::byte{0xFF},
        std::byte{0xEE},
        std::byte{0xDD},
        std::byte{0xCC},
        std::byte{0xBB},
        std::byte{0xAA},
        std::byte{0x99},
        std::byte{0x88},
        std::byte{0x77},
        std::byte{0x66},
        std::byte{0x55},
        std::byte{0x44},
        std::byte{0x33},
        std::byte{0x22},
        std::byte{0x11},
        std::byte{0x00}
    };

    auto encoded = encode_freenet(decoded);
    REQUIRE_THAT(encoded, Equals("-~7dzLuqmYh3ZlVEMyIRAA"));
    REQUIRE(decode_freenet(encoded) == decoded);

    encoded = encode_standard(decoded);
    REQUIRE_THAT(encoded, Equals("/+7dzLuqmYh3ZlVEMyIRAA=="));
    REQUIRE(decode_standard(encoded) == decoded);

    std::u8string u8str{u8"Hello World! こんにちは 世界"};

    encoded = encode_u8str_standard(u8str);
    REQUIRE_THAT(
        encoded, Equals("SGVsbG8gV29ybGQhIOOBk+OCk+OBq+OBoeOBryDkuJbnlYw=")
    );
    auto decoded_str = decode_str_standard(encoded);
    auto decoded_u8str = str_to_u8str(decoded_str);
    REQUIRE(decoded_u8str == u8str);
    decoded_u8str = decode_u8str_standard(encoded);
    REQUIRE(decoded_u8str == u8str);

    encoded = encode_u8str_freenet(u8str);
    REQUIRE_THAT(
        encoded, Equals("SGVsbG8gV29ybGQhIOOBk~OCk~OBq~OBoeOBryDkuJbnlYw")
    );
    decoded_str = decode_str_freenet(encoded);
    decoded_u8str = str_to_u8str(decoded_str);
    REQUIRE(decoded_u8str == u8str);
    decoded_u8str = decode_u8str_freenet(encoded);
    REQUIRE(decoded_u8str == u8str);

    const std::string str{"Hello, World!"};

    encoded = encode_str_standard(str);
    REQUIRE_THAT(encoded, Equals("SGVsbG8sIFdvcmxkIQ=="));
    decoded_str = decode_str_standard(encoded);
    REQUIRE(decoded_str == str);
    u8str = str_to_u8str(str);
    decoded_u8str = decode_u8str_standard(encoded);
    REQUIRE(decoded_u8str == u8str);

    encoded = encode_str_freenet(str);
    REQUIRE_THAT(encoded, Equals("SGVsbG8sIFdvcmxkIQ"));
    decoded_str = decode_str_freenet(encoded);
    REQUIRE(decoded_str == str);
    u8str = str_to_u8str(str);
    decoded_u8str = decode_u8str_freenet(encoded);
    REQUIRE(decoded_u8str == u8str);
}

TEST_CASE("Fields related functions are working", "[library][support]")
{
    using namespace support::field;

    SECTION("testBytesToInt")
    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{2}, std::byte{2}
        };

        auto out_int = bytes_to_integer<int>(bytes, 0);

        REQUIRE(out_int == 33685760);
    }
}
