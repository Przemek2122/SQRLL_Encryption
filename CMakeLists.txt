cmake_minimum_required(VERSION 3.20)
project(SQRLL_Encryption)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME}
    Sources/EncryptionUtil.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC Sources)
