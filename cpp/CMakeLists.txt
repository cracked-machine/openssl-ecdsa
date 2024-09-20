cmake_minimum_required(VERSION 3.15)

project(ecdsa)

add_compile_options("-g")
add_executable(ecdsa ecdsa.cpp)
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

target_link_libraries(ecdsa ${OPENSSL_LIBRARIES})