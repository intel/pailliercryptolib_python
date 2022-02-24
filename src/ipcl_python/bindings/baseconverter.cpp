// Copyright (C) 2021-2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "include/baseconverter.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace baseconverter {
std::string hex2dec(std::string val) {
  std::string res;
  do {
    unsigned int remainder = divide(hexSet, val, 10);
    res.push_back(decSet[remainder]);
  } while (!val.empty() && !(val.length() == 1 && val[0] == hexSet[0]));
  std::reverse(res.begin(), res.end());
  return res;
}
std::string dec2hex(std::string val) {
  std::string res;

  do {
    unsigned int remainder = divide(decSet, val, 16);
    res.push_back(hexSet[remainder]);
  } while (!val.empty() && !(val.length() == 1 && val[0] == decSet[0]));
  std::reverse(res.begin(), res.end());
  return res;
}

unsigned int divide(const std::string& baseSet, std::string& x,
                    unsigned int y) {
  std::string quotient;
  size_t length = x.length();

  for (size_t i = 0; i < length; ++i) {
    size_t j = i + 1 + x.length() - length;
    if (x.length() < j) break;

    unsigned int value = getdec(baseSet, x.substr(0, j));

    quotient.push_back(baseSet[value / y]);
    x = getbase(baseSet, value % y) + x.substr(j);
  }

  unsigned int remainder = getdec(baseSet, x);
  size_t n = quotient.find_first_not_of(baseSet[0]);
  if (n != std::string::npos)
    x = quotient.substr(n);
  else
    x.clear();

  return remainder;
}

std::string getbase(const std::string& baseSet, unsigned int val) {
  unsigned int n = static_cast<unsigned int>(baseSet.length());
  std::string res;

  do {
    res.push_back(baseSet[val % n]);
    val /= n;
  } while (val > 0);

  std::reverse(res.begin(), res.end());
  return res;
}
unsigned int getdec(const std::string& baseSet, const std::string& val) {
  unsigned int n = static_cast<unsigned int>(baseSet.length());
  unsigned int res = 0;
  for (size_t i = 0; i < val.length(); ++i) {
    res *= n;
    int c = baseSet.find(val[i]);
    if (c == std::string::npos) throw std::runtime_error("Invalid character");

    res += static_cast<unsigned int>(c);
  }
  return res;
}

std::string BN2dec(const BigNumber& bn) {
  std::string s_hex;
  bn.num2hex(s_hex);
  size_t start = s_hex.find_first_not_of(" \n\r\t\f\b");
  s_hex = s_hex.substr(start + 2);

  return hex2dec(s_hex);
}

};  // namespace baseconverter
