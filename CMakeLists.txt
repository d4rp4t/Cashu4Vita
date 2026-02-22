cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{VITASDK} AND NOT CMAKE_TOOLCHAIN_FILE STREQUAL "")
  if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  endif()
  set(VITA_BUILD ON)
endif()

project(VitaCashu C CXX)

if(VITA_BUILD)
  include("${VITASDK}/share/vita.cmake" REQUIRED)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VITA_APP_NAME "VitaCashu")
set(VITA_TITLEID  "VCSH03338")
set(VITA_VERSION  "01.00")

set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_UNINSTALL OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_UTILS OFF CACHE BOOL "" FORCE)

add_subdirectory(deps/secp256k1)
add_subdirectory(deps/qcbor)
add_subdirectory(deps/cjson)
target_include_directories(cjson PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/cjson>
        $<INSTALL_INTERFACE:include>
)

# bc-ur C++ library + C wrapper
set(BCUR_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/bc-ur/src)
add_library(bcur STATIC
        ${BCUR_SRC_DIR}/bytewords.cpp
        ${BCUR_SRC_DIR}/fountain-decoder.cpp
        ${BCUR_SRC_DIR}/fountain-encoder.cpp
        ${BCUR_SRC_DIR}/fountain-utils.cpp
        ${BCUR_SRC_DIR}/random-sampler.cpp
        ${BCUR_SRC_DIR}/ur-decoder.cpp
        ${BCUR_SRC_DIR}/ur-encoder.cpp
        ${BCUR_SRC_DIR}/ur.cpp
        ${BCUR_SRC_DIR}/utils.cpp
        ${BCUR_SRC_DIR}/xoshiro256.cpp
        ${BCUR_SRC_DIR}/crc32.c
        ${BCUR_SRC_DIR}/memzero.c
        ${BCUR_SRC_DIR}/sha2.c
)
target_include_directories(bcur PUBLIC ${BCUR_SRC_DIR})

add_library(quirc STATIC
        deps/quirc/lib/quirc.c
        deps/quirc/lib/decode.c
        deps/quirc/lib/identify.c
        deps/quirc/lib/version_db.c
)
target_include_directories(quirc PUBLIC deps/quirc/lib)
# use float instead of double to avoid 8-byte alignment faults on ARM
target_compile_definitions(quirc PRIVATE QUIRC_FLOAT_TYPE=float QUIRC_USE_TGMATH)

add_executable(${PROJECT_NAME}
        main.c
        cashu/protocol.c
        cashu/models.c
        cashu/encoding.c
        cashu/json.c
        cashu/http.c
        cashu/utils.c
        cashu/bcur.cpp
        deps/qrcodegen/c/qrcodegen.c
        abstractions/storage.c
        abstractions/wallet.c
        abstractions/exports.c
        abstractions/qr_reader.c
)
target_include_directories(${PROJECT_NAME} PRIVATE
        deps/qrcodegen/c
        abstractions)

target_link_libraries(${PROJECT_NAME}
        vita2d
        bcur
        quirc
        secp256k1
        qcbor
        cjson
        curl
        ssl
        crypto
        z
        zstd
        mbedtls
        mbedcrypto
        mbedx509
        SceDisplay_stub
        SceGxm_stub
        SceCtrl_stub
        ScePgf_stub
        SceCommonDialog_stub
        SceAppMgr_stub
        SceCamera_stub
        SceNet_stub
        SceNetCtl_stub
        SceSysmodule_stub
        m
        stdc++)

if(NOT CMAKE_CROSSCOMPILING)
    set(CRYPTO_SOURCES cashu/protocol.c cashu/utils.c)
    set(CRYPTO_INCLUDES deps/secp256k1/include /opt/homebrew/include)
    set(CRYPTO_LIBS secp256k1 mbedcrypto m)

    foreach(test hash_to_curve message_blinding)
        add_executable(test_${test} tests/test_${test}.c ${CRYPTO_SOURCES})
        target_include_directories(test_${test} PRIVATE ${CRYPTO_INCLUDES})
        target_link_directories(test_${test} PRIVATE /opt/homebrew/lib)
        target_link_libraries(test_${test} ${CRYPTO_LIBS})
    endforeach()

    add_executable(test_serialization
            tests/test_serialization.c
            cashu/encoding.c
            cashu/models.c
            cashu/utils.c
            tests/testing_utils.h
    )
    target_include_directories(test_serialization PRIVATE
            deps/qcbor/inc deps/secp256k1/include /opt/homebrew/include)
    target_link_directories(test_serialization PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_serialization qcbor secp256k1 m)

    add_executable(test_json
            tests/test_json.c
            cashu/json.c
            cashu/models.c
            cashu/utils.c
            tests/testing_utils.h
    )
    target_include_directories(test_json PRIVATE
            deps/cjson deps/secp256k1/include /opt/homebrew/include)
    target_link_directories(test_json PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_json cjson secp256k1 m)

    add_executable(test_storage
            tests/test_storage.c
            abstractions/storage.c
            cashu/json.c
            cashu/models.c
            cashu/utils.c
            tests/testing_utils.h
    )
    target_include_directories(test_storage PRIVATE
            deps/cjson deps/secp256k1/include /opt/homebrew/include abstractions)
    target_link_directories(test_storage PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_storage cjson secp256k1 m)

    add_executable(test_network
            tests/test_network.c
            cashu/http_host.c
            cashu/protocol.c
            cashu/json.c
            cashu/models.c
            cashu/utils.c
            tests/testing_utils.h
    )
    target_include_directories(test_network PRIVATE
            deps/cjson deps/secp256k1/include /opt/homebrew/include)
    target_link_directories(test_network PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_network curl cjson secp256k1 mbedcrypto m)

    add_executable(test_wallet
            tests/test_wallet.c
            cashu/http_host.c
            cashu/protocol.c
            cashu/json.c
            cashu/models.c
            cashu/encoding.c
            cashu/utils.c
            abstractions/storage.c
            abstractions/wallet.c
            tests/testing_utils.h
    )
    target_include_directories(test_wallet PRIVATE
            deps/cjson deps/qcbor/inc deps/secp256k1/include
            /opt/homebrew/include abstractions)
    target_link_directories(test_wallet PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_wallet curl cjson qcbor secp256k1 mbedcrypto m)

    add_executable(test_bcur
            tests/test_bcur.c
            cashu/bcur.cpp
    )
    target_include_directories(test_bcur PRIVATE deps/bc-ur/src)
    target_link_libraries(test_bcur bcur)
endif()

if(VITA_BUILD)
  vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME})
  vita_create_vpk(${PROJECT_NAME}.vpk ${VITA_TITLEID} ${PROJECT_NAME}.self
          VERSION ${VITA_VERSION}
          NAME ${VITA_APP_NAME})
endif()
