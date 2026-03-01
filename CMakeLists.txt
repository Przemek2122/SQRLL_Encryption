cmake_minimum_required(VERSION 3.20)
project(SQRLL_Encryption_All LANGUAGES CXX)

# Should tests be enabled?
# PROJECT_IS_TOP_LEVEL -> If building this file only - ON
# If building this file as added in other cmake it will be OFF
option(SQRLL_ENCRYPTION_BUILD_TESTS "Build SQRLL_Encryption tests" ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (SQRLL_ENCRYPTION_BUILD_TESTS)
    include(CTest)
    enable_testing()
    add_subdirectory(Tests)
else()
    add_subdirectory(Encryption)
endif()
