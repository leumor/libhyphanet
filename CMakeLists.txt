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

# ---- Declare library ----

add_library(
    libhyphanet_libhyphanet

    include/libhyphanet/libhyphanet.h

    include/libhyphanet/keys.h
    source/keys.cpp

    include/libhyphanet/support.h
    source/support.cpp

    include/libhyphanet/support/base64.h
    source/support/base64.cpp
)
add_library(libhyphanet::libhyphanet ALIAS libhyphanet_libhyphanet)

include(GenerateExportHeader)
generate_export_header(
    libhyphanet_libhyphanet
    BASE_NAME libhyphanet
    EXPORT_FILE_NAME export/libhyphanet/libhyphanet_export.h
    CUSTOM_CONTENT_FROM_VARIABLE pragma_suppress_c4251
)

if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(libhyphanet_libhyphanet PUBLIC LIBHYPHANET_STATIC_DEFINE)
endif()

set_target_properties(
    libhyphanet_libhyphanet PROPERTIES
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
# target_link_libraries(libhyphanet_libhyphanet PRIVATE Boost::algorithm)
target_include_directories(libhyphanet_libhyphanet PRIVATE ${Boost_INCLUDE_DIRS})

find_package(ICU REQUIRED COMPONENTS i18n uc)
target_link_libraries(libhyphanet_libhyphanet PRIVATE ICU::i18n ICU::uc)

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
