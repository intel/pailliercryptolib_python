// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <ippcp.h>
#include <ippcpdefs.h>
#include <ippversion.h>
#include <pybind11/numpy.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <functional>
#include <iostream>
#include <sstream>
#include <utility>

#include "include/baseconverter.h"
#include "ipcl/ciphertext.hpp"
#include "ipcl/keygen.hpp"
#include "ipcl/plaintext.hpp"

#ifndef SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
#define SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
class py_ipclKeyPair {
 public:
  static pybind11::tuple generate_keypair(int64_t n_length = 1024,
                                          bool enable_DJN = true);
};

void def_ipclPublicKey(pybind11::module&);
void def_ipclPrivateKey(pybind11::module&);
void def_BigNumber(pybind11::module&);
void def_ipclPlainText(pybind11::module&);
void def_ipclCipherText(pybind11::module&);

namespace ipclPythonUtils {
std::pair<int, pybind11::list> BN2pylist(const BigNumber& bn);
BigNumber pylist2BN(const pybind11::list& l_bn);
BigNumber pylist2BN(int length, const pybind11::list& l_bn);
pybind11::tuple getTupleIpclPubKey(const ipcl::PublicKey* pk);
ipcl::PublicKey* setIpclPubKey(const pybind11::tuple& t_pk);
};  // namespace ipclPythonUtils

#endif  // SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
