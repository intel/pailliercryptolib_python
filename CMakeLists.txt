# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.15.1)

project(IPCL_PYTHON VERSION 1.0.0 LANGUAGES C CXX)

if(CMAKE_BUILD_TYPE)
  set(RELEASE_TYPES
      Debug
      Release
      RelWithDebInfo
      MinSizeRel)
  list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
  if(${INDEX_FOUND} EQUAL -1)
    message(
      FATAL_ERROR
        "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel"
      )
  endif()
else()
  set(CMAKE_BUILD_TYPE Release)
endif()

# TODO(skmono): Assess if C++17 is necessary
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Create compilation database compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS "-O2")
set(CMAKE_CXX_FLAGS "-O2 -fpermissive -Wno-as-needed")


#---------------------------------------------------
option(IPCL_PYTHON_TEST "Enable testing" ON)
option(IPCL_PYTHON_DOCS "Enable document building" OFF)
option(IPCL_PYTHON_ENABLE_OMP "Use OpenMP for IPCL backend" OFF)
if(IPCL_PYTHON_ENABLE_OMP)
  find_package(OpenMP)
  if(NOT OpenMP)
    option(IPCL_PYTHON_ENABLE_OMP "Use OpenMP for IPCL backend" OFF)
    message(STATUS "OpenMP not found - disabling for build")
  endif()
endif()


message(STATUS "CMAKE_BUILD_TYPE:           ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_COMPILER:           ${CMAKE_C_COMPILER}")
message(STATUS "IPCL_PYTHON_TEST:           ${IPCL_PYTHON_TEST}")
message(STATUS "IPCL_PYTHON_DOCS:           ${IPCL_PYTHON_DOCS}")
message(STATUS "IPCL_PYTHON_ENABLE_OMP:     ${IPCL_PYTHON_ENABLE_OMP}")

set(IPCL_PYTHON_FORWARD_CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
    -DCMAKE_CXX_STANDARD_REQUIRED=${CMAKE_CXX_STANDARD_REQUIRED}
    -DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}
    -DCMAKE_EXPORT_COMPILE_COMMANDS=${CMAKE_EXPORT_COMPILE_COMMANDS}
    -DCMAKE_POSITION_INDEPENDENT_CODE=${CMAKE_POSITION_INDEPENDENT_CODE}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

set(IPCL_BINDINGS_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/ipcl_python/bindings)
set(IPCL_BINDINGS_INC_DIR ${IPCL_BINDINGS_SRC_DIR}/include)
set(IPCL_BINDINGS_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "IPCL_BINDINGS_SRCS_DIR : ${IPCL_BINDINGS_SRC_DIR}")
include(lib/ipcl.cmake)
include(lib/pybind11.cmake)

FetchContent_GetProperties(pybind11)

find_package(OpenSSL REQUIRED)

set(IPCL_BINDINGS_SRCS ${IPCL_BINDINGS_SRC_DIR}/ipcl_bindings.cpp
${IPCL_BINDINGS_SRC_DIR}/baseconverter.cpp
${IPCL_BINDINGS_SRC_DIR}/ipcl_bindings_classes.cpp)

pybind11_add_module(ipcl_bindings ${IPCL_BINDINGS_SRCS})

target_include_directories(ipcl_bindings PUBLIC ${PYTHON_INCLUDE_DIRS} ${IPCL_BINDINGS_INC_DIR} ${IPCL_BINDINGS_SRC_DIR})
target_link_libraries(ipcl_bindings PUBLIC libipcl OpenSSL::SSL OpenSSL::Crypto -lnuma)
if(IPCL_PYTHON_ENABLE_OMP)
  find_package(OpenMP REQUIRED)
  target_link_libraries(ipcl_bindings PUBLIC OpenMP::OpenMP_CXX)
endif()
target_link_libraries(ipcl_bindings INTERFACE ext_fate_fixedpoint)
