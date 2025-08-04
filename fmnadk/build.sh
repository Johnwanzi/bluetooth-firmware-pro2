#!/bin/bash

# FMNADK Static Library Build Script
# 简化版本 - 只生成静态库，编译错误时保留现场
# 错误时保持终端打开并停留在当前目录

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

export TOOL_CHAIN_PREFIX="arm-none-eabi"

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查必要文件
if [ ! -f "CMakeLists.txt" ]; then
    print_error "CMakeLists.txt not found. Please run from fmnadk directory."
    echo "Current directory: $(pwd)"
    echo "Available files:"
    ls -la
    echo ""
    echo "Type 'exit' to close terminal"
    # 保持在当前目录，启动新的bash shell
    exec bash
fi

if [ ! -f "../toolchain.cmake" ]; then
    print_error "toolchain.cmake not found in parent directory."
    echo "Current directory: $(pwd)"
    echo "Available files:"
    ls -la
    echo ""
    echo "Type 'exit' to close terminal"
    # 保持在当前目录，启动新的bash shell
    exec bash
fi

if [ ! -d "../ble-firmware" ]; then
    print_error "ble-firmware directory not found in parent directory."
    echo "Current directory: $(pwd)"
    echo "Available files:"
    ls -la
    echo ""
    echo "Type 'exit' to close terminal"
    # 保持在当前目录，启动新的bash shell
    exec bash
fi

print_info "Building FMNADK static library..."

# 创建构建目录
rm -rf build
mkdir -p build
cd build

# 配置CMake
print_info "Configuring CMake..."
print_info "Using toolchain: $TOOL_CHAIN_PREFIX"
cmake .. -DCMAKE_BUILD_TYPE=Release -DTOOL_CHAIN_PREFIX=$TOOL_CHAIN_PREFIX

if [ $? -ne 0 ]; then
    print_error "CMake configuration failed!"
    echo ""
    echo "=== CMake Configuration Failed ==="
    echo "Current directory: $(pwd)"
    echo "Available files:"
    ls -la
    echo ""
    echo "Debugging suggestions:"
    echo "1. Check toolchain: which arm-none-eabi-gcc"
    echo "2. Check CMakeLists.txt for errors"
    echo "3. Try: cmake .. -DCMAKE_BUILD_TYPE=Release -DUSE_CRYPTO=TRUE"
    echo "4. Type 'exit' to close terminal"
    echo ""
    # 退出build目录，回到fmnadk目录
    cd ..
    exec bash
fi

# 构建库
print_info "Building library..."
make -j$(nproc)

if [ $? -eq 0 ]; then
    print_info "Build completed successfully!"
    if [ -f "libFMNADK.a" ]; then
        LIB_SIZE=$(stat -c%s libFMNADK.a)
        print_info "Library size: $(numfmt --to=iec $LIB_SIZE)"
        print_info "Library location: $(pwd)/libFMNADK.a"
    fi
    # 退出build目录，回到fmnadk目录
    cd ..
    print_info "Build completed! You are now in the fmnadk directory."
    exec bash
else
    print_error "Build failed!"
    echo ""
    echo "=== Build Failed ==="
    echo "Current directory: $(pwd)"
    echo "Available files:"
    ls -la
    echo ""
    echo "Debugging suggestions:"
    echo "1. Check compilation errors above"
    echo "2. Try building again: make"
    echo "3. Check CMake configuration: cmake .."
    echo "4. Type 'exit' to close terminal"
    echo ""
    # 退出build目录，回到fmnadk目录
    cd ..
    exec bash
fi 