cmake_minimum_required(VERSION 3.13)
project(SentinelPass)

# 1. Find LLVM (Required)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

# 2. Add LLVM definitions and include directories
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS})

# 3. Define the Pass Library
add_llvm_library(SentinelPass MODULE
  SentinelPass.cpp
  PLUGIN_TOOL
  opt
)
