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

cmake --build $BUILD_DIR --target test_hash_to_curve test_message_blinding test_serialization test_json test_storage test_network test_wallet

echo "== hash_to_curve =="
$BUILD_DIR/test_hash_to_curve

echo "== message_blinding =="
$BUILD_DIR/test_message_blinding

echo "== token_serialization =="
$BUILD_DIR/test_serialization

echo "== json_encode_decode =="
$BUILD_DIR/test_json

echo "==== storage ===="
$BUILD_DIR/test_storage

echo "==== network ===="
$BUILD_DIR/test_network

echo "==== wallet ===="
$BUILD_DIR/test_wallet
