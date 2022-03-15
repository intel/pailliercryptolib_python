// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "ipcl/bignum.h"

#ifndef SRC_IPCL_PYTHON_BINDINGS_INCLUDE_BASECONVERTER_H_
#define SRC_IPCL_PYTHON_BINDINGS_INCLUDE_BASECONVERTER_H_

namespace baseconverter {
std::string hex2dec(std::string val);
std::string dec2hex(std::string val);

unsigned int divide(const std::string& baseSet, std::string& x, unsigned int y);
const char decSet[] = "0123456789";
const char hexSet[] = "0123456789abcdef";

std::string getbase(const std::string& baseSet, unsigned int val);
unsigned int getdec(const std::string& baseSet, const std::string& val);
std::string BN2dec(const ipcl::BigNumber& bn);
};  // namespace baseconverter

#endif  // SRC_IPCL_PYTHON_BINDINGS_INCLUDE_BASECONVERTER_H_
