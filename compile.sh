#!/bin/bash
# Make sure script stops on errors
set -e

# Navigate to emsdk
cd emsdk

# Source the Emscripten environment
source ./emsdk_env.sh

# Go back to the project root
cd ..

# Compile C++ to WebAssembly/JS
emcc main.cpp \
  -o index.js \
  -s EXPORTED_FUNCTIONS='["_main","_unpack_buffer","_open_file","_get_unpacked_ptr","_get_unpacked_size","_check_version_information","_malloc","_free","_isRemoveCertChecked"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -O3 \
  --bind \
  -lembind

echo "Build complete!"
