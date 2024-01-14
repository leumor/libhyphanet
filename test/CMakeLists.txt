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

# ---- Tests ----

add_executable(libhyphanet_test 
source/libhyphanet_test.cpp
source/test_support.cpp
source/test_crypto.cpp
)

target_link_libraries(
    libhyphanet_test PRIVATE
    libhyphanet::libhyphanet
    Catch2::Catch2WithMain
)
target_compile_features(libhyphanet_test PRIVATE cxx_std_20)

catch_discover_tests(libhyphanet_test)

# ---- End-of-file commands ----

add_folders(Test)
