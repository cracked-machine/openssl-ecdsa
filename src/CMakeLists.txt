cmake_minimum_required(VERSION 3.15)
project(ecdsa)
add_compile_options("-g")
add_compile_options(-Wall)

# We shouldn't leave this enabled!!!
add_compile_options(-Wno-deprecated-declarations)

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED IMPORTED_TARGET openssl)

add_executable(ecdsa_sign_verify_legacy ${CMAKE_SOURCE_DIR}/ecdsa_sign_verify_legacy.cpp)
target_link_libraries(ecdsa_sign_verify_legacy PUBLIC PkgConfig::OPENSSL)

add_executable(ecdsa_sign_verify ${CMAKE_SOURCE_DIR}/ecdsa_sign_verify.cpp)
target_link_libraries(ecdsa_sign_verify PUBLIC PkgConfig::OPENSSL)

add_executable(parse_cms ${CMAKE_SOURCE_DIR}/parse_cms.cpp)
target_link_libraries(parse_cms PUBLIC PkgConfig::OPENSSL)

add_executable(cms_verify ${CMAKE_SOURCE_DIR}/cms_verify.cpp)
target_link_libraries(cms_verify PUBLIC PkgConfig::OPENSSL)

add_executable(managed ${CMAKE_SOURCE_DIR}/managed.cpp)
target_link_libraries(managed PUBLIC PkgConfig::OPENSSL)
