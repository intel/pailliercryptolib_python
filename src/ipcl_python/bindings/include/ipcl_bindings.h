// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// #include "ipcl/ippcrypto/ippcp.h"
// #include "ipcl/ippcrypto/ippcpdefs.h"
// #include <ippversion.h>
#include <pybind11/numpy.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include "ipcl/ipcl.hpp"

#ifdef IPCL_PYTHON_USE_QAT
#include "ipcl/context.hpp"
#endif  // IPCL_PYTHON_USE_QAT

#ifndef SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
#define SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
class py_ipclKeyPair {
 public:
  static pybind11::tuple generate_keypair(int64_t n_length = 1024,
                                          bool enable_DJN = true);
};

#ifdef IPCL_PYTHON_USE_QAT
class py_ipclContext {
 public:
  static bool initializeContext(std::string runtime_choice) {
    return ipcl::initializeContext(runtime_choice);
  }
  static bool terminateContext() { return ipcl::terminateContext(); }
  static bool isQATRunning() { return ipcl::isQATRunning(); }
  static bool isQATActive() { return ipcl::isQATActive(); }
};

class py_ipclHybridControl {
 public:
  static void setHybridMode(ipcl::HybridMode mode);
  static void setHybridOff() { ipcl::setHybridOff(); }
  static ipcl::HybridMode getHybridMode() { return ipcl::getHybridMode(); }
};

#endif  // IPCL_PYTHON_USE_QAT
void def_ipclPublicKey(pybind11::module&);
void def_ipclPrivateKey(pybind11::module&);
void def_BigNumber(pybind11::module&);
void def_ipclPlainText(pybind11::module&);
void def_ipclCipherText(pybind11::module&);

namespace ipclPythonUtils {
pybind11::tuple getTupleIpclPubKey(const ipcl::PublicKey* pk);
ipcl::PublicKey* setIpclPubKey(const pybind11::tuple& t_pk);
BigNumber pyByte2BN(const pybind11::bytes& data);
pybind11::bytes BN2bytes(const BigNumber& bn);
};  // namespace ipclPythonUtils

#endif  // SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_H_
