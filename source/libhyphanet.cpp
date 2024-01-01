#include <string>

#include "libhyphanet/libhyphanet.h"

#include <fmt/core.h>

exported_class::exported_class()
    : m_name {fmt::format("{}", "libhyphanet")}
{
}

auto exported_class::name() const -> char const*
{
  return m_name.c_str();
}
