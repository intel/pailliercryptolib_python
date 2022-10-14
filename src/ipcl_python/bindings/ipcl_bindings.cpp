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

  // py::class_<ipcl::keyPair>(m, "keyPair");

  // PaillierKeyPair and generate_keypair pymodule
  py::class_<py_ipclKeyPair>(m, "ipclKeypair")
      .def_static("generate_keypair", &py_ipclKeyPair::generate_keypair)
      .def_static("generate_keypair", [](int64_t n_length, bool enable_DJN) {
        return py_ipclKeyPair::generate_keypair(n_length, enable_DJN);
      });

#ifdef IPCL_PYTHON_USE_QAT
  py::class_<py_ipclContext>(m, "ipclContext")
      .def_static("initializeContext", &py_ipclContext::initializeContext)
      .def_static("terminateContext", &py_ipclContext::terminateContext)
      .def_static("isQATRunning", &py_ipclContext::isQATRunning)
      .def_static("isQATActive", &py_ipclContext::isQATActive);
#endif  // IPCL_PYTHON_USE_QAT
  def_ipclPublicKey(m);
  def_ipclPrivateKey(m);
  def_ipclPlainText(m);
  def_ipclCipherText(m);
  def_BigNumber(m);
}

namespace ipclPythonUtils {
std::pair<int, py::list> BN2pylist(const BigNumber& bn) {
  int bnBitLen;
  Ipp32u* bnData;
  ippsRef_BN(nullptr, &bnBitLen, &bnData, bn);
  size_t length = BITSIZE_WORD(bnBitLen);
  std::vector<Ipp32u> tmp(bnData, bnData + length);
  py::list l_dt = py::cast(tmp);
  return std::make_pair(length, l_dt);
}

BigNumber pylist2BN(const py::list& l_bn) {
  std::vector<Ipp32u> bnData = py::cast<std::vector<Ipp32u>>(l_bn);
  return BigNumber(bnData.data(), bnData.size());
}

BigNumber pylist2BN(size_t length, const py::list& l_bn) {
  std::vector<Ipp32u> bnData = py::cast<std::vector<Ipp32u>>(l_bn);
  return BigNumber(bnData.data(), length);
}

py::tuple getTupleIpclPubKey(const ipcl::PublicKey* pk) {
  py::tuple ret;
  int pk_length = pk->getBits();
  bool isDJN = pk->isDJN();
  if (isDJN) {  // DJN scheme
    auto l_n = BN2pylist(pk->getN());
    auto l_hs = BN2pylist(pk->getHS());
    int randbits = pk->getRandBits();
    ret = py::make_tuple(1, l_n.second, pk_length, l_hs.second, randbits);
  } else {  // Paillier scheme
    auto l_n = BN2pylist(pk->getN());
    ret = py::make_tuple(0, l_n.second, pk_length, 0, 0);
  }
  return ret;
}

ipcl::PublicKey* setIpclPubKey(const py::tuple& t_pk) {
  ipcl::PublicKey* ret;
  int scheme = py::cast<int>(t_pk[0]);
  py::list l_n = t_pk[1];
  BigNumber n = pylist2BN(l_n);
  int pk_length = py::cast<int>(t_pk[2]);

  if (scheme == 0) {  // Paillier scheme
    ret = new ipcl::PublicKey(n, pk_length);
  } else {  // DJN scheme
    py::list l_hs = t_pk[3];
    BigNumber hs = pylist2BN(l_hs);
    int randbits = py::cast<int>(t_pk[4]);
    ret = new ipcl::PublicKey(n, pk_length);
    ret->setDJN(hs, randbits);
  }
  return ret;
}
};  // namespace ipclPythonUtils
