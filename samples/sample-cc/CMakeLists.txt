cmake_minimum_required(VERSION 3.14)
project(MyCppApp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

# 声明依赖的第三方库（通过 find_package / target_link_libraries）
find_package(OpenSSL REQUIRED)
find_package(ZLIB 1.2.11 REQUIRED)
find_package(CURL 7.68.0)

add_library(core STATIC src/core.cpp)
add_library(utils SHARED src/utils.cpp)

add_executable(app src/main.cpp)
target_link_libraries(app
    PRIVATE
        core
        utils
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        CURL::libcurl
        pthread
)
