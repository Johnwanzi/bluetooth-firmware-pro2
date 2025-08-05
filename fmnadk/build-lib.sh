#!/bin/bash

# Fmnadk Static Library Build Script

export TOOL_CHAIN_PREFIX="arm-none-eabi"

print_info() {
    echo -e "\033[0;32m[INFO]\033[0m $1"
}

print_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

print_info "Building fmnadk static library..."

# Create build directory
rm -rf build
mkdir -p build
cd build

# Configure CMake
print_info "Configuring CMake..."
print_info "Using toolchain: $TOOL_CHAIN_PREFIX"
cmake .. -DCMAKE_BUILD_TYPE=Debug -DTOOL_CHAIN_PREFIX=$TOOL_CHAIN_PREFIX

if [ $? -ne 0 ]; then
    print_error "CMake configuration failed!"
    exit 1
fi

# Build library
print_info "Building library..."
make -j$(nproc)
make install

if [ $? -eq 0 ]; then
    cd ..
    print_info "Build completed!"
else
    print_error "Build failed!"
    exit 1
fi 

rm -rf build