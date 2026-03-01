cmake_minimum_required(VERSION 3.20)

project(SQRLL_Encryption LANGUAGES CXX)

add_library(SQRLL_Encryption
        Sources/SQRLLEncryption.cpp
)

target_include_directories(SQRLL_Encryption
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Sources
)

target_compile_features(SQRLL_Encryption PUBLIC cxx_std_20)