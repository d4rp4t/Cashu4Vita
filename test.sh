#!/bin/bash
set -e

BUILD_DIR=/tmp/vitacashu-test
rm -rf $BUILD_DIR

cmake -B $BUILD_DIR \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_TOOLCHAIN_FILE="" \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -S .

cmake --build $BUILD_DIR --target test_hash_to_curve

$BUILD_DIR/test_hash_to_curve
