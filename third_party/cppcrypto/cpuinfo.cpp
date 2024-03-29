/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#include "cpuinfo.h"
#include <array>
#include <bitset>
#include <string>
#include <vector>
#ifndef _MSC_VER
#include <cpuid.h>
#else
#include <intrin.h>
#endif

namespace cppcrypto {

const cpu_info::cpu_info_impl cpu_info::impl_;

cpu_info::cpu_info_impl::cpu_info_impl()
{
    enable();
}

void cpu_info::cpu_info_impl::enable()
{
#ifdef _MSC_VER
    std::array<int, 4> cpui;
#else
    std::array<unsigned int, 4> cpui;
#endif

#ifdef _MSC_VER
    __cpuid(cpui.data(), 0);
    int ids = cpui[0];
#else
    auto ids = __get_cpuid_max(0, nullptr);
#endif

    if (ids >= 1) {
#ifdef _MSC_VER
        __cpuidex(cpui.data(), 1, 0);
#else
        __cpuid_count(1, 0, cpui[0], cpui[1], cpui[2], cpui[3]);
#endif
        ecx1_ = cpui[2u];
        edx1_ = cpui[3u];
    }

    if (ids >= 7) {
#ifdef _MSC_VER
        __cpuidex(cpui.data(), 7, 0);
#else
        __cpuid_count(7, 0, cpui[0], cpui[1], cpui[2], cpui[3]);
#endif
        ebx7_ = cpui[1u];
        ecx7_ = cpui[2u];
    }

#ifdef _MSC_VER
    __cpuid(cpui.data(), 0x80000000);
    unsigned int extended_ids = cpui[0u];
#else
    auto extended_ids = __get_cpuid_max(0x80000000, nullptr);
#endif

    if (extended_ids >= 0x80000001) {
#ifdef _MSC_VER
        __cpuidex(cpui.data(), 0x80000001, 0);
#else
        __cpuid_count(0x80000001, 0, cpui[0], cpui[1], cpui[2], cpui[3]);
#endif
        ecx81_ = cpui[2u];
        edx81_ = cpui[3u];
    }
}

void cpu_info::cpu_info_impl::disable()
{
    ecx1_.reset();
    edx1_.reset();
    ebx7_.reset();
    ecx7_.reset();
    ecx81_.reset();
    edx81_.reset();
}

} // namespace cppcrypto
