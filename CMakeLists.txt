cmake_minimum_required(VERSION 3.30)
project(VitaCashu C)

set(CMAKE_C_STANDARD 11)

add_executable(VitaCashu main.c
        crypto.c
        crypto.h)
add_subdirectory(deps/secp256k1)
target_link_libraries(${PROJECT_NAME}
        secp256k1
        mbedtls
        mbedcrypto
        mbedx509
        m)

target_include_directories(VitaCashu PRIVATE
        $ENV{VITASDK}/arm-vita-eabi/include
)