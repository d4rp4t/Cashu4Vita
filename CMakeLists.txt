cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{VITASDK} AND NOT CMAKE_TOOLCHAIN_FILE STREQUAL "")
  if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  endif()
  set(VITA_BUILD ON)
endif()

project(VitaCashu C)

if(VITA_BUILD)
  include("${VITASDK}/share/vita.cmake" REQUIRED)
endif()

set(CMAKE_C_STANDARD 11)

set(VITA_APP_NAME "VitaCashu")
set(VITA_TITLEID  "VCSH00001")
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

add_executable(${PROJECT_NAME}
        main.c
        cashu/protocol.c
        cashu/models.c
        cashu/encoding.c
        cashu/json.c
        cashu/utils.c
)


target_link_libraries(${PROJECT_NAME}
        secp256k1
        qcbor
        cjson
        mbedtls
        mbedcrypto
        mbedx509
        m)

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
endif()

if(VITA_BUILD)
  vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME})
  vita_create_vpk(${PROJECT_NAME}.vpk ${VITA_TITLEID} ${PROJECT_NAME}.self
          VERSION ${VITA_VERSION}
          NAME ${VITA_APP_NAME})
endif()
