cmake_minimum_required(VERSION 3.20)

project(SQRLL_Encryption LANGUAGES CXX)

add_library(SQRLL_Encryption
    Sources/SQRLLEncryption.cpp
)

target_include_directories(SQRLL_Encryption
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Sources
)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # -march=native for selection of instruction which are supported by compiling cpu
    target_compile_options(${PROJECT_NAME} PRIVATE -O3 -march=native)
endif()

target_compile_features(SQRLL_Encryption PUBLIC cxx_std_20)