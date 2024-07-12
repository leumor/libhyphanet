cmake_minimum_required(VERSION 3.14)

include(cmake/prelude.cmake)

project(
  libhyphanet
  VERSION 0.1.0
  DESCRIPTION "Short description"
  HOMEPAGE_URL "https://example.com/"
  LANGUAGES CXX
)

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

set(CMAKE_OSX_DEPLOYMENT_TARGET 14.3)

if(BUILD_SHARED_LIBS)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# ---- Declare library ----
add_library(objlib_cppcrypto OBJECT
  third_party/cppcrypto/alignedarray.h
  third_party/cppcrypto/block_cipher.h
  third_party/cppcrypto/block_cipher.cpp
  third_party/cppcrypto/portability.h
  third_party/cppcrypto/rijndael.h
  third_party/cppcrypto/rijndael.cpp
  third_party/cppcrypto/rijndael-impl.h
)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
  target_sources(objlib_cppcrypto PRIVATE
    third_party/cppcrypto/rijndael-impl-aesni-common.h
    third_party/cppcrypto/rijndael-impl-aesni.cpp
    third_party/cppcrypto/cpuinfo.h
    third_party/cppcrypto/cpuinfo.cpp
  )

  if(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    target_compile_options(objlib_cppcrypto PRIVATE -maes -msse4.1)
  endif()
endif()

file(GLOB_RECURSE cppcrypto_files third_party/cppcrypto/*)
set_source_files_properties(
  ${cppcrypto_files}
  TARGET_DIRECTORY objlib_cppcrypto
  PROPERTIES
  SKIP_LINTING ON
)
add_library(
  libhyphanet_libhyphanet

  include/libhyphanet/libhyphanet.h

  include/libhyphanet/key.h
  source/key.cpp

  include/libhyphanet/key/user.h
  include/libhyphanet/key/impl/user.h
  source/key/user.cpp

  include/libhyphanet/key/node.h
  source/key/node.cpp

  include/libhyphanet/support.h
  source/support.cpp

  include/libhyphanet/crypto.h
  source/crypto.cpp

  include/libhyphanet/support/base64.h
  source/support/base64.cpp

  include/libhyphanet/block.h
  source/block.cpp

  include/libhyphanet/bucket.h
  source/bucket.cpp

  $<TARGET_OBJECTS:objlib_cppcrypto>
)
add_library(libhyphanet::libhyphanet ALIAS libhyphanet_libhyphanet)

include(GenerateExportHeader)
generate_export_header(
  libhyphanet_libhyphanet
  BASE_NAME libhyphanet
  EXPORT_FILE_NAME export/libhyphanet/libhyphanet_export.h
  CUSTOM_CONTENT_FROM_VARIABLE pragma_suppress_c4251
)

# Fix Windows build of std::min and std::max which has min/max macro by default
target_compile_definitions(libhyphanet_libhyphanet PRIVATE NOMINMAX)

if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(libhyphanet_libhyphanet PUBLIC LIBHYPHANET_STATIC_DEFINE)
endif()

if(ENABLE_COVERAGE)
  target_compile_options(libhyphanet_libhyphanet PRIVATE -fkeep-inline-functions -fkeep-static-functions)
endif()

set_target_properties(
  libhyphanet_libhyphanet PROPERTIES
  C_VISIBILITY_PRESET hidden
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  EXPORT_NAME libhyphanet
  OUTPUT_NAME libhyphanet
)

target_include_directories(
  libhyphanet_libhyphanet ${warning_guard}
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party>"
)

target_include_directories(
  libhyphanet_libhyphanet SYSTEM
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/export>"
)

target_compile_features(libhyphanet_libhyphanet PUBLIC cxx_std_20)

find_package(fmt CONFIG REQUIRED)
target_link_libraries(libhyphanet_libhyphanet PRIVATE fmt::fmt)

find_package(Microsoft.GSL CONFIG REQUIRED)
target_link_libraries(libhyphanet_libhyphanet PRIVATE Microsoft.GSL::GSL)

find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(libhyphanet_libhyphanet PRIVATE cryptopp::cryptopp)

find_package(Boost REQUIRED COMPONENTS)

# target_link_libraries(libhyphanet_libhyphanet PRIVATE Boost::multiprecision)
target_include_directories(libhyphanet_libhyphanet PRIVATE ${Boost_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_check_modules(gmp REQUIRED IMPORTED_TARGET gmp)
target_link_libraries(libhyphanet_libhyphanet PRIVATE PkgConfig::gmp)

find_package(ICU REQUIRED COMPONENTS i18n uc data)
target_link_libraries(libhyphanet_libhyphanet PRIVATE ICU::i18n ICU::uc ICU::data)

# ---- Install rules ----
if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

# ---- Developer mode ----
if(NOT libhyphanet_DEVELOPER_MODE)
  return()
elseif(NOT PROJECT_IS_TOP_LEVEL)
  message(
    AUTHOR_WARNING
    "Developer mode is intended for developers of libhyphanet"
  )
endif()

include(cmake/dev-mode.cmake)
