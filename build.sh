#!/bin/bash
set -e
if [[ "$(docker images -q vitacashu-build:latest 2>/dev/null)" == "" ]]; then
    docker build --load --platform linux/amd64 -t vitacashu-build .
fi

docker run --platform linux/amd64 --rm \
    -v "$(pwd):/project" \
    -w /project \
    vitacashu-build \
    bash -c "cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build"
