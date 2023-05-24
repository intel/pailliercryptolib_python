// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <nanobind/nanobind.h>
#include <nanobind/ndarray.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

// #include "ipcl/context.hpp"
#include "ipcl/ipcl.hpp"

#ifndef SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_HPP_
#define SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_HPP_
class py_ipclKeyPair {
 public:
  static nanobind::tuple generate_keypair(int64_t n_length = 1024,
                                          bool enable_DJN = true);
};

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

void def_ipclPublicKey(nanobind::module_&);
void def_ipclPrivateKey(nanobind::module_&);
void def_BigNumber(nanobind::module_&);
void def_ipclPlainText(nanobind::module_&);
void def_ipclCipherText(nanobind::module_&);

namespace ipclPythonUtils {
nanobind::tuple getTupleIpclPubKey(const ipcl::PublicKey& pk);
ipcl::PublicKey setIpclPubKey(const nanobind::tuple& t_pk);
BigNumber pyByte2BN(const nanobind::bytes& data);
nanobind::bytes BN2bytes(const BigNumber& bn);
nanobind::bytes BN2bytes(const std::shared_ptr<BigNumber>& bn);
};  // namespace ipclPythonUtils

#endif  // SRC_IPCL_PYTHON_BINDINGS_INCLUDE_IPCL_BINDINGS_HPP_
