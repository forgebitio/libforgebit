# Unit tests include private headers and prefer the static target when available.

set(FORGEBIT_TEST_LIB forgebit_static)
if(NOT TARGET forgebit_static)
    set(FORGEBIT_TEST_LIB forgebit_shared)
endif()

set(FORGEBIT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# Test-only signer for compact JWS fixtures.
add_library(forgebit_test_tools STATIC tools/sign_fixture.c)
target_include_directories(forgebit_test_tools
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tools
    PRIVATE ${FORGEBIT_SRC_DIR}
)
target_link_libraries(forgebit_test_tools PUBLIC PkgConfig::SODIUM)
if(FORGEBIT_ENABLE_SANITIZERS)
    target_compile_options(forgebit_test_tools PRIVATE ${FORGEBIT_SANITIZER_FLAGS})
endif()

function(forgebit_add_test name)
    add_executable(${name} ${name}.c)
    target_include_directories(${name} PRIVATE ${FORGEBIT_SRC_DIR})
    target_link_libraries(${name} PRIVATE ${FORGEBIT_TEST_LIB} forgebit_test_tools)
    if(FORGEBIT_ENABLE_SANITIZERS)
        target_compile_options(${name} PRIVATE ${FORGEBIT_SANITIZER_FLAGS})
        target_link_options(${name} PRIVATE ${FORGEBIT_SANITIZER_FLAGS})
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

forgebit_add_test(test_base64url)
forgebit_add_test(test_json)
forgebit_add_test(test_jws)
forgebit_add_test(test_claims_time)
forgebit_add_test(test_hwid)
forgebit_add_test(test_vectors)
forgebit_add_test(test_c_specific)
