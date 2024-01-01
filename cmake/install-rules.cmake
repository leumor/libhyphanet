if(PROJECT_IS_TOP_LEVEL)
  set(
      CMAKE_INSTALL_INCLUDEDIR "include/libhyphanet-${PROJECT_VERSION}"
      CACHE STRING ""
  )
  set_property(CACHE CMAKE_INSTALL_INCLUDEDIR PROPERTY TYPE PATH)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# find_package(<package>) call for consumers to find this project
set(package libhyphanet)

install(
    DIRECTORY
    include/
    "${PROJECT_BINARY_DIR}/export/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT libhyphanet_Development
)

install(
    TARGETS libhyphanet_libhyphanet
    EXPORT libhyphanetTargets
    RUNTIME #
    COMPONENT libhyphanet_Runtime
    LIBRARY #
    COMPONENT libhyphanet_Runtime
    NAMELINK_COMPONENT libhyphanet_Development
    ARCHIVE #
    COMPONENT libhyphanet_Development
    INCLUDES #
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

write_basic_package_version_file(
    "${package}ConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)

# Allow package maintainers to freely override the path for the configs
set(
    libhyphanet_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${package}"
    CACHE STRING "CMake package config location relative to the install prefix"
)
set_property(CACHE libhyphanet_INSTALL_CMAKEDIR PROPERTY TYPE PATH)
mark_as_advanced(libhyphanet_INSTALL_CMAKEDIR)

install(
    FILES cmake/install-config.cmake
    DESTINATION "${libhyphanet_INSTALL_CMAKEDIR}"
    RENAME "${package}Config.cmake"
    COMPONENT libhyphanet_Development
)

install(
    FILES "${PROJECT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${libhyphanet_INSTALL_CMAKEDIR}"
    COMPONENT libhyphanet_Development
)

install(
    EXPORT libhyphanetTargets
    NAMESPACE libhyphanet::
    DESTINATION "${libhyphanet_INSTALL_CMAKEDIR}"
    COMPONENT libhyphanet_Development
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
