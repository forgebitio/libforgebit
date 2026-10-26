cmake_minimum_required(VERSION 3.16)
project(forgebit VERSION 0.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(FORGEBIT_BUILD_SHARED "Build the shared forgebit library" ON)
option(FORGEBIT_BUILD_STATIC "Build the static forgebit library" ON)
option(FORGEBIT_BUILD_TESTS "Build the forgebit test suite" ON)
option(FORGEBIT_ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

set(FORGEBIT_SOURCES
    src/base64url.c
    src/json.c
    src/jws.c
    src/claims.c
    src/crypto.c
    src/result.c
    src/verifier.c
    src/codes.c
)

set(FORGEBIT_SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -g)

function(forgebit_configure_target target_name linkage)
    target_include_directories(${target_name}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    # Link libsodium at build time. For the static archive, keep the
    # dependency out of the installed export (CMake would otherwise embed
    # the non-portable PkgConfig::SODIUM target name). ForgebitConfig.cmake
    # re-attaches libsodium for Forgebit::static consumers.
    if(linkage STREQUAL "static")
        target_link_libraries(${target_name} PRIVATE $<BUILD_INTERFACE:PkgConfig::SODIUM>)
    else()
        target_link_libraries(${target_name} PRIVATE PkgConfig::SODIUM)
    endif()
    set_target_properties(${target_name} PROPERTIES OUTPUT_NAME forgebit)
    if(FORGEBIT_ENABLE_SANITIZERS)
        target_compile_options(${target_name} PRIVATE ${FORGEBIT_SANITIZER_FLAGS})
        target_link_options(${target_name} PRIVATE ${FORGEBIT_SANITIZER_FLAGS})
    endif()
endfunction()

set(FORGEBIT_INSTALL_TARGETS "")

if(FORGEBIT_BUILD_SHARED)
    add_library(forgebit_shared SHARED ${FORGEBIT_SOURCES})
    forgebit_configure_target(forgebit_shared shared)
    set_target_properties(forgebit_shared PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        EXPORT_NAME shared
        INSTALL_NAME_DIR "@rpath"
        BUILD_WITH_INSTALL_NAME_DIR ON
    )
    add_library(Forgebit::shared ALIAS forgebit_shared)
    list(APPEND FORGEBIT_INSTALL_TARGETS forgebit_shared)
endif()

if(FORGEBIT_BUILD_STATIC)
    add_library(forgebit_static STATIC ${FORGEBIT_SOURCES})
    forgebit_configure_target(forgebit_static static)
    set_target_properties(forgebit_static PROPERTIES
        EXPORT_NAME static
    )
    add_library(Forgebit::static ALIAS forgebit_static)
    list(APPEND FORGEBIT_INSTALL_TARGETS forgebit_static)
endif()

if(NOT FORGEBIT_BUILD_SHARED AND NOT FORGEBIT_BUILD_STATIC)
    message(FATAL_ERROR "At least one of FORGEBIT_BUILD_SHARED or FORGEBIT_BUILD_STATIC must be ON")
endif()

# Default alias used by in-tree consumers.
if(TARGET forgebit_shared)
    add_library(Forgebit::forgebit ALIAS forgebit_shared)
elseif(TARGET forgebit_static)
    add_library(Forgebit::forgebit ALIAS forgebit_static)
endif()

# Install: libraries, headers, pkg-config, CMake package config

configure_file(cmake/forgebit.pc.in ${CMAKE_CURRENT_BINARY_DIR}/forgebit.pc @ONLY)

set(FORGEBIT_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/Forgebit)

install(TARGETS ${FORGEBIT_INSTALL_TARGETS}
    EXPORT ForgebitTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN ".DS_Store" EXCLUDE
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/forgebit.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
install(FILES LICENSE
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/forgebit
)

install(EXPORT ForgebitTargets
    FILE ForgebitTargets.cmake
    NAMESPACE Forgebit::
    DESTINATION ${FORGEBIT_INSTALL_CMAKEDIR}
)

configure_package_config_file(
    cmake/ForgebitConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ForgebitConfig.cmake
    INSTALL_DESTINATION ${FORGEBIT_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ForgebitConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ForgebitConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ForgebitConfigVersion.cmake
    DESTINATION ${FORGEBIT_INSTALL_CMAKEDIR}
)

# Tests

if(FORGEBIT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Formatting (clang-format)

find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format clang-format-22 clang-format-18 clang-format-17)
if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE FORGEBIT_FORMAT_SOURCES
        CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/tools/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/tools/*.h
    )
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i --style=file ${FORGEBIT_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Formatting C sources with clang-format"
        VERBATIM
    )
    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror --style=file ${FORGEBIT_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Checking C source formatting with clang-format"
        VERBATIM
    )
else()
    message(STATUS "clang-format not found; 'format' / 'format-check' targets disabled")
endif()
