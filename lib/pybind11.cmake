# Copyright (C) 2021-2022 Intel Corporation

include(FetchContent)
find_package(Git)

FetchContent_Declare(pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
)

FetchContent_MakeAvailable(pybind11)
