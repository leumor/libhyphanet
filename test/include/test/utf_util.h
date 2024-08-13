#ifndef INCLUDE_TEST_UTF_UTIL_H
#define INCLUDE_TEST_UTF_UTIL_H

#include <array>
#include <cstddef>
#include <gsl/util>
#include <limits>
#include <string>
#include <unicode/umachine.h>
#include <unicode/unistr.h>

namespace utf_util {

const size_t max_uchar = std::numeric_limits<UChar>::max();

constexpr std::array<UChar, max_uchar> calculate_all_chars()
{
    std::array<UChar, max_uchar> all_chars{};
    for (UChar char_value = 0; char_value < max_uchar; ++char_value) {
        // The low and high surrogates are no valid unicode characters.
        if ((char_value >= 0xDC00 && char_value <= 0xDFFF)
            || (char_value >= 0XD800 && char_value <= 0xDBFF)) {
            all_chars.at(char_value) = ' ';
        }
        else {
            all_chars.at(char_value) = char_value;
        }
    }
    return all_chars;
}

/**
 * Contains all unicode characters except the low and high surrogates (they are
 * no valid characters and constructing strings with them will cause ICU to
 * replace them with the default replacement character). Even 0x0000 is
 * included.
 */
constexpr std::array<UChar, max_uchar> all_characters = calculate_all_chars();

// printable ascii symbols
static const std::array<UChar, 28> printable_ascii{
    ' ', '!', '@', '#', '$',  '%',  '^',  '&', '(', ')', '+', '=', '{', '}',
    '[', ']', ':', ';', '\\', '\"', '\'', ',', '<', '>', '.', '?', '~', '`'
};

// stressed UTF chars values
static const std::array<UChar, 175> stressed_utf{
    // ÉâûĔĭņşÊãüĕĮŇŠËäýĖįňšÌåþėİŉŢÍæÿĘıŊţÎçĀęĲŋŤÏèāĚĳŌťÐéĂěĴōŦÑêăĜĵŎŧ
    u'\u00c9',
    u'\u00e2',
    u'\u00fb',
    u'\u0114',
    u'\u012d',
    u'\u0146',
    u'\u015f',
    u'\u00ca',
    u'\u00e3',
    u'\u00fc',
    u'\u0115',
    u'\u012e',
    u'\u0147',
    u'\u0160',
    u'\u00cb',
    u'\u00e4',
    u'\u00fd',
    u'\u0116',
    u'\u012f',
    u'\u0148',
    u'\u0161',
    u'\u00cc',
    u'\u00e5',
    u'\u00fe',
    u'\u0117',
    u'\u0130',
    u'\u0149',
    u'\u0162',
    u'\u00cd',
    u'\u00e6',
    u'\u00ff',
    u'\u0118',
    u'\u0131',
    u'\u014a',
    u'\u0163',
    u'\u00ce',
    u'\u00e7',
    u'\u0100',
    u'\u0119',
    u'\u0132',
    u'\u014b',
    u'\u0164',
    u'\u00cf',
    u'\u00e8',
    u'\u0101',
    u'\u011a',
    u'\u0133',
    u'\u014c',
    u'\u0165',
    u'\u00d0',
    u'\u00e9',
    u'\u0102',
    u'\u011b',
    u'\u0134',
    u'\u014d',
    u'\u0166',
    u'\u00d1',
    u'\u00ea',
    u'\u0103',
    u'\u011c',
    u'\u0135',
    u'\u014e',
    u'\u0167',
    // ÒëĄĝĶŏŨÓìąĞķŐũÔíĆğĸőŪÕîćĠĹŒūÖïĈġĺœŬ×ðĉĢĻŔŭØñĊģļŕŮÙòċĤĽŖůÚóČĥľŗŰ
    u'\u00d2',
    u'\u00eb',
    u'\u0104',
    u'\u011d',
    u'\u0136',
    u'\u014f',
    u'\u0168',
    u'\u00d3',
    u'\u00ec',
    u'\u0105',
    u'\u011e',
    u'\u0137',
    u'\u0150',
    u'\u0169',
    u'\u00d4',
    u'\u00ed',
    u'\u0106',
    u'\u011f',
    u'\u0138',
    u'\u0151',
    u'\u016a',
    u'\u00d5',
    u'\u00ee',
    u'\u0107',
    u'\u0120',
    u'\u0139',
    u'\u0152',
    u'\u016b',
    u'\u00d6',
    u'\u00ef',
    u'\u0108',
    u'\u0121',
    u'\u013a',
    u'\u0153',
    u'\u016c',
    u'\u00d7',
    u'\u00f0',
    u'\u0109',
    u'\u0122',
    u'\u013b',
    u'\u0154',
    u'\u016d',
    u'\u00d8',
    u'\u00f1',
    u'\u010a',
    u'\u0123',
    u'\u013c',
    u'\u0155',
    u'\u016e',
    u'\u00d9',
    u'\u00f2',
    u'\u010b',
    u'\u0124',
    u'\u013d',
    u'\u0156',
    u'\u016f',
    u'\u00da',
    u'\u00f3',
    u'\u010c',
    u'\u0125',
    u'\u013e',
    u'\u0157',
    u'\u0170',
    // ÛôčĦĿŘűÜõĎħŀřŲÝöďĨŁŚųÞ÷ĐĩłśŴßøđĪŃŜŵàùĒīńŝŶáúēĬŅŞŷ
    u'\u00db',
    u'\u00f4',
    u'\u010d',
    u'\u0126',
    u'\u013f',
    u'\u0158',
    u'\u0171',
    u'\u00dc',
    u'\u00f5',
    u'\u010e',
    u'\u0127',
    u'\u0140',
    u'\u0159',
    u'\u0172',
    u'\u00dd',
    u'\u00f6',
    u'\u010f',
    u'\u0128',
    u'\u0141',
    u'\u015a',
    u'\u0173',
    u'\u00de',
    u'\u00f7',
    u'\u0110',
    u'\u0129',
    u'\u0142',
    u'\u015b',
    u'\u0174',
    u'\u00df',
    u'\u00f8',
    u'\u0111',
    u'\u012a',
    u'\u0143',
    u'\u015c',
    u'\u0175',
    u'\u00e0',
    u'\u00f9',
    u'\u0112',
    u'\u012b',
    u'\u0144',
    u'\u015d',
    u'\u0176',
    u'\u00e1',
    u'\u00fa',
    u'\u0113',
    u'\u012c',
    u'\u0145',
    u'\u015e',
    u'\u0177'
};

template<std::size_t N>
std::string uchar_arr_to_str(const std::array<UChar, N>& arr)
{
    std::string str_utf8;
    icu::UnicodeString str{arr.data(), gsl::narrow_cast<int32_t>(arr.size())};
    str.toUTF8String(str_utf8);
    return str_utf8;
}

} // namespace utf_util

#endif /* INCLUDE_TEST_UTF_UTIL_H */
