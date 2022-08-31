# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(ExternalProject)
MESSAGE(STATUS "Configuring Intel Paillier Cryptosystem Library")
set(IPCL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/ext_ipcl)
set(IPCL_GIT_REPO_URL https://github.com/intel/pailliercryptolib.git)
set(IPCL_GIT_LABEL development)
set(IPCL_SRC_DIR ${IPCL_PREFIX}/src/ext_ipcl/)

set(IPCL_CXX_FLAGS "${IPCL_PYTHON_FORWARD_CMAKE_ARGS}")

ExternalProject_Add(
  ext_ipcl
  GIT_REPOSITORY ${IPCL_GIT_REPO_URL}
  GIT_TAG ${IPCL_GIT_LABEL}
  PREFIX ${IPCL_PREFIX}
  INSTALL_DIR ${IPCL_PREFIX}
  CMAKE_ARGS ${IPCL_CXX_FLAGS}
             -DCMAKE_INSTALL_PREFIX=${IPCL_PREFIX}
             -DIPCL_TEST=OFF
             -DIPCL_BENCHMARK=OFF
             -DIPCL_DOCS=OFF
             -DIPCL_SHARED=OFF
             -DIPCL_ENABLE_OMP=${IPCL_PYTHON_ENABLE_OMP}
  UPDATE_COMMAND ""
)

ExternalProject_Get_Property(ext_ipcl SOURCE_DIR BINARY_DIR)

add_library(libipcl INTERFACE)
add_dependencies(libipcl ext_ipcl)

file(STRINGS /etc/os-release LINUX_ID REGEX "^ID=")
string(REGEX REPLACE "ID=\(.*)" "\\1" LINUX_ID "${LINUX_ID}")
if(${LINUX_ID} STREQUAL "ubuntu")
  target_link_libraries(libipcl INTERFACE
        ${IPCL_PREFIX}/lib/libipcl.a)
else()
  # non debian systems install ipcl under lib64
  target_link_libraries(libipcl INTERFACE
  ${IPCL_PREFIX}/lib64/libipcl.a)
endif()

target_include_directories(libipcl INTERFACE ${IPCL_PREFIX}/include)
