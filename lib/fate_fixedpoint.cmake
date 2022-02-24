# Copyright (C) 2021-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(ExternalProject)
set(FATE_FIXEDPOINT_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/ext_fate_fixedpoint)
set(FATE_FIXEDPOINT_URL https://raw.githubusercontent.com/FederatedAI/FATE/master/python/federatedml/secureprotol/fixedpoint.py)

ExternalProject_Add(
  ext_fate_fixedpoint
  PREFIX ${FATE_FIXEDPOINT_PREFIX}
  URL ${FATE_FIXEDPOINT_URL}
  DOWNLOAD_NO_EXTRACT 1
  BUILD_COMMAND ""
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND ""
)
add_custom_command(TARGET ext_fate_fixedpoint PRE_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  ${FATE_FIXEDPOINT_PREFIX}/src/fixedpoint.py
  ${IPCL_BINDINGS_SRC_DIR}
)
