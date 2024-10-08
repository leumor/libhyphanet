cmake_minimum_required(VERSION 3.14)

project(libhyphanetTests LANGUAGES CXX)

include(../cmake/project-is-top-level.cmake)
include(../cmake/folders.cmake)

# ---- Dependencies ----
if(PROJECT_IS_TOP_LEVEL)
  find_package(libhyphanet REQUIRED)
  enable_testing()
endif()

find_package(Catch2 REQUIRED)
include(Catch)

if(BUILD_SHARED_LIBS)
  add_compile_definitions(libhyphanet_libhyphanet_EXPORTS)
endif()

# ---- Tests ----
add_executable(libhyphanet_test
  source/libhyphanet_test.cpp
  source/test_support.cpp
  source/test_crypto.cpp
  source/test_keys.cpp
  source/test_bucket.cpp

  include/test/utf_util.h
)

target_include_directories(
  libhyphanet_test ${warning_guard}
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../source>"
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
)

find_package(cryptopp CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

target_link_libraries(
  libhyphanet_test PRIVATE
  libhyphanet::libhyphanet
  Catch2::Catch2WithMain
  cryptopp::cryptopp
  fmt::fmt
  ICU::i18n ICU::uc ICU::data
  PkgConfig::gmp
  objlib_cppcrypto
)
target_compile_features(libhyphanet_test PRIVATE cxx_std_20)

# Fix Windows build of std::min and std::max which has min/max macro by default
target_compile_definitions(libhyphanet_test PRIVATE NOMINMAX)

# Disable WD4275 warnings
target_compile_options(libhyphanet_test PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/wd4275>)

catch_discover_tests(libhyphanet_test)

# ---- End-of-file commands ----
add_folders(Test)
