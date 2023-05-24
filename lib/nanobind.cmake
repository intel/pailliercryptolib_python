# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(FetchContent)
find_package(Git)

FetchContent_Declare(nanobind
    GIT_REPOSITORY https://github.com/wjakob/nanobind.git
)

FetchContent_MakeAvailable(nanobind)
