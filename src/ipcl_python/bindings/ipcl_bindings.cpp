// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "include/ipcl_bindings.h"

namespace py = pybind11;

py::tuple py_ipclKeyPair::generate_keypair(int64_t n_length, bool enable_DJN) {
  ipcl::keyPair keys = ipcl::generateKeypair(n_length, enable_DJN);
  return py::make_tuple(keys.pub_key, keys.priv_key);
}

PYBIND11_MODULE(ipcl_bindings, m) {
  m.doc() = "Python wrapper for Intel ipp-crypto Paillier cryptosystem";

  py::class_<ipcl::keyPair>(m, "keyPair");

  // PaillierKeyPair and generate_keypair pymodule
  py::class_<py_ipclKeyPair>(m, "ipclKeypair")
      .def_static("generate_keypair", &py_ipclKeyPair::generate_keypair)
      .def_static("generate_keypair", [](int64_t n_length, bool enable_DJN) {
        return py_ipclKeyPair::generate_keypair(n_length, enable_DJN);
      });

  def_ipclPublicKey(m);
  def_ipclPrivateKey(m);
  def_ipclEncryptedNumber(m);
  def_BigNumber(m);
}

namespace py_ippUtils {
std::pair<int, py::list> BN2pylist(const ipcl::BigNumber& bn) {
  int bnBitLen;
  Ipp32u* bnData;
  ippsRef_BN(nullptr, &bnBitLen, &bnData, bn);
  size_t length = ipcl::BITSIZE_WORD(bnBitLen);
  py::list l_dt;
  for (size_t i = 0; i < length; i++) l_dt.append(bnData[i]);
  return std::make_pair(length, l_dt);
}

ipcl::BigNumber pylist2BN(const py::list& l_bn) {
  size_t length = l_bn.size();
  Ipp32u* bnData = new Ipp32u[length];
  for (size_t i = 0; i < length; ++i)
    bnData[i] = py::cast<unsigned int>(l_bn[i]);
  return ipcl::BigNumber(bnData, length);
}

ipcl::BigNumber pylist2BN(size_t length, const py::list& l_bn) {
  Ipp32u* bnData = new Ipp32u[length];
  for (size_t i = 0; i < length; ++i)
    bnData[i] = py::cast<unsigned int>(l_bn[i]);
  return ipcl::BigNumber(bnData, length);
}
};  // namespace py_ippUtils
