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
add_subdirectory(deps/secp256k1)
add_subdirectory(deps/qcbor)

add_executable(${PROJECT_NAME}
        main.c
        cashu/protocol.c
        cashu/models.c
        cashu/utils.c
        tests/test_blinded_messages.c)

target_link_libraries(${PROJECT_NAME}
        secp256k1
        qcbor
        mbedtls
        mbedcrypto
        mbedx509
        m)

if(NOT CMAKE_CROSSCOMPILING)
    add_executable(test_hash_to_curve
            tests/test_hash_to_curve.c
            cashu/protocol.c
            cashu/utils.c)
    target_include_directories(test_hash_to_curve PRIVATE
            deps/secp256k1/include
            /opt/homebrew/include)
    target_link_directories(test_hash_to_curve PRIVATE /opt/homebrew/lib)
    target_link_libraries(test_hash_to_curve secp256k1 mbedcrypto m)
endif()

if(VITA_BUILD)
  vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME})
  vita_create_vpk(${PROJECT_NAME}.vpk ${VITA_TITLEID} ${PROJECT_NAME}.self
          VERSION ${VITA_VERSION}
          NAME ${VITA_APP_NAME})
endif()
