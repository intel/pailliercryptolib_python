# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(FetchContent)
MESSAGE(STATUS "Configuring Intel Paillier Cryptosystem Library")
set(IPCL_GIT_REPO_URL https://github.com/intel-sandbox/libraries.security.cryptography.homomorphic-encryption.glade.pailliercryptolib.git)
set(IPCL_GIT_LABEL v2.0.0-rc)

# set IPCL flags
if(IPCL_PYTHON_ENABLE_QAT)
  set(IPCL_ENABLE_QAT ON)
endif()

if(IPCL_PYTHON_DETECT_CPU_RUNTIME)
  set(IPCL_DETECT_CPU_RUNTIME ON)
endif()

set(IPCL_ENABLE_OMP OFF)
if(IPCL_PYTHON_ENABLE_OMP)
  if(OpenMP_FOUND)
    set(IPCL_ENABLE_OMP ON)
  endif()
endif()

set(IPCL_SHARED ON)
set(IPCL_TEST OFF)
set(IPCL_BENCHMARK OFF)
set(IPCL_INTERNAL_PYTHON_BUILD ON)

FetchContent_Declare(
  ipcl
  GIT_REPOSITORY ${IPCL_GIT_REPO_URL}
  GIT_TAG ${IPCL_GIT_LABEL}
)
FetchContent_MakeAvailable(ipcl)
