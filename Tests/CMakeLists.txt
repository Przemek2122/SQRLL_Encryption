cmake_minimum_required(VERSION 3.20)
project(SQRLL_Encryption_Tests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── GoogleTest via FetchContent ──────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
)

FetchContent_MakeAvailable(googletest)

# ── MbedTLS (For AES and ChaCha20 Benchmarks) ────────────────────────
FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG        v3.6.0
)
# Disable unnecessary MbedTLS build targets
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedtls programs" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedtls tests" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "Disable warnings as errors in mbedtls" FORCE)
FetchContent_MakeAvailable(mbedtls)

# ── Encryption library from sibling directory ────────────────────────
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Encryption ${CMAKE_CURRENT_BINARY_DIR}/Encryption)

# ── Test executable ──────────────────────────────────────────────────
add_executable(${PROJECT_NAME}
    EncryptionTests.cpp
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        SQRLL_Encryption
        GTest::gtest_main
        mbedcrypto
)

# ── CTest integration ───────────────────────────────────────────────
include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})
