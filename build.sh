#!/usr/bin/env bash

# set -e

##### KEY #####
export BT_SIG_PK_FILE=$(pwd)/temp.pk
echo "$BT_SIG_PK" > $BT_SIG_PK_FILE

# Set default toolchain prefix if not already defined
if [ -z "$TOOL_CHAIN_PREFIX" ]; then
    export TOOL_CHAIN_PREFIX="arm-none-eabi"
fi

# Set default RTT debug enable if not already defined
export RTT_DEBUG_ENABLE=0

##### CLEANUP #####
rm -rf artifacts
rm -rf artifacts_signed 

##### BUILD #####
# remove build folder if exists
rm -rf _build
# build
mkdir -p _build
cmake  -G 'Ninja'  -S ./  -B ./_build -DTOOL_CHAIN_PREFIX=$TOOL_CHAIN_PREFIX -DCMAKE_BUILD_TYPE=Debug -DRTT_DEBUG_ENABLE=$RTT_DEBUG_ENABLE
cmake --build ./_build -- -j$(nproc)
utils/hash.py -t bluetooth -f artifacts/OnekeyPro2BTFW_APP.bin > artifacts/sha256.txt
# remove build folder
rm -f $BT_SIG_PK_FILE
rm -rf _build
