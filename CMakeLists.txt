cmake_minimum_required(VERSION 3.30)
project(VitaCashu C)

set(CMAKE_C_STANDARD 11)

add_executable(VitaCashu main.c
        cashu/protocol.c
        cashu/protocol.h
        cashu/models.c
        cashu/models.h)
add_subdirectory(deps/secp256k1)
add_subdirectory(deps/cjson)
add_subdirectory(deps/qcbor)
target_link_libraries(${PROJECT_NAME}
        secp256k1
        qcbor
        mbedtls
        mbedcrypto
        mbedx509
        m)

target_include_directories(VitaCashu PRIVATE
        $ENV{VITASDK}/arm-vita-eabi/include
)