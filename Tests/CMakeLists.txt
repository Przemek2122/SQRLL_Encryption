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
)

# ── CTest integration ───────────────────────────────────────────────
include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})
