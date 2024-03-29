// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "include/ipcl_bindings.hpp"

#include <iostream>

namespace py = pybind11;

PYBIND11_MAKE_OPAQUE(BigNumber);

py::tuple py_ipclKeyPair::generate_keypair(int64_t n_length, bool enable_DJN) {
  ipcl::KeyPair keys = ipcl::generateKeypair(n_length, enable_DJN);
  return py::make_tuple(keys.pub_key, keys.priv_key);
}

void py_ipclHybridControl::setHybridMode(ipcl::HybridMode mode) {
  ipcl::setHybridMode(mode);
}

PYBIND11_MODULE(ipcl_bindings, m) {
  m.doc() = "Python wrapper for Intel ipp-crypto Paillier cryptosystem";

  // PaillierKeyPair and generate_keypair pymodule
  py::class_<py_ipclKeyPair>(m, "ipclKeypair")
      .def_static("generate_keypair", &py_ipclKeyPair::generate_keypair)
      .def_static("generate_keypair", [](int64_t n_length, bool enable_DJN) {
        return py_ipclKeyPair::generate_keypair(n_length, enable_DJN);
      });

  py::class_<py_ipclContext>(m, "context")
      .def_static("initializeContext", &py_ipclContext::initializeContext)
      .def_static("terminateContext", &py_ipclContext::terminateContext)
      .def_static("isQATRunning", &py_ipclContext::isQATRunning)
      .def_static("isQATActive", &py_ipclContext::isQATActive);

  py::enum_<ipcl::HybridMode>(m, "hybridMode")
      .value("OPTIMAL", ipcl::HybridMode::OPTIMAL)
      .value("QAT", ipcl::HybridMode::QAT)
      .value("PREF_QAT90", ipcl::HybridMode::PREF_QAT90)
      .value("PREF_QAT80", ipcl::HybridMode::PREF_QAT80)
      .value("PREF_QAT70", ipcl::HybridMode::PREF_QAT70)
      .value("PREF_QAT60", ipcl::HybridMode::PREF_QAT60)
      .value("HALF", ipcl::HybridMode::HALF)
      .value("PREF_IPP60", ipcl::HybridMode::PREF_IPP60)
      .value("PREF_IPP70", ipcl::HybridMode::PREF_IPP70)
      .value("PREF_IPP80", ipcl::HybridMode::PREF_IPP80)
      .value("PREF_IPP90", ipcl::HybridMode::PREF_IPP90)
      .value("IPP", ipcl::HybridMode::IPP)
      .value("UNDEFINED", ipcl::HybridMode::UNDEFINED)
      .export_values();

  py::class_<py_ipclHybridControl>(m, "hybridControl")
      .def_static("setHybridMode", &py_ipclHybridControl::setHybridMode)
      .def_static("setHybridOff", &py_ipclHybridControl::setHybridOff)
      .def_static("getHybridMode", &py_ipclHybridControl::getHybridMode);

  def_ipclPublicKey(m);
  def_ipclPrivateKey(m);
  def_ipclPlainText(m);
  def_ipclCipherText(m);
  def_BigNumber(m);
}

namespace ipclPythonUtils {
py::tuple getTupleIpclPubKey(const ipcl::PublicKey& pk) {
  py::tuple ret;
  int pk_length = pk.getBits();
  bool isDJN = pk.isDJN();
  if (isDJN) {  // DJN scheme
    auto l_n = BN2bytes(pk.getN());
    auto l_hs = BN2bytes(pk.getHS());
    int randbits = pk.getRandBits();
    ret = py::make_tuple(1, l_n, pk_length, l_hs, randbits);
  } else {  // Paillier scheme
    auto l_n = BN2bytes(pk.getN());
    ret = py::make_tuple(0, l_n, pk_length, 0, 0);
  }
  return ret;
}

ipcl::PublicKey setIpclPubKey(const py::tuple& t_pk) {
  ipcl::PublicKey ret;
  int scheme = py::cast<int>(t_pk[0]);
  py::bytes l_n = t_pk[1];
  BigNumber n = pyByte2BN(l_n);
  int pk_length = py::cast<int>(t_pk[2]);

  if (scheme == 0) {  // Paillier scheme
    ret.create(n, pk_length);
  } else {  // DJN scheme
    py::bytes l_hs = t_pk[3];
    BigNumber hs = pyByte2BN(l_hs);
    int randbits = py::cast<int>(t_pk[4]);
    ret.create(n, pk_length, hs, randbits);
  }
  return ret;
}

BigNumber pyByte2BN(const py::bytes& data) {
  py::buffer_info buffer_info(py::buffer(data).request());
  unsigned char* chardata = reinterpret_cast<unsigned char*>(buffer_info.ptr);
  size_t length = static_cast<size_t>(buffer_info.size);

  size_t new_length = (length + 3) >> 2;
  Ipp32u* data32 = reinterpret_cast<Ipp32u*>(chardata);

  // check MSB if length % 4 != 0
  size_t rmdr = length & 3;
  if (rmdr) {  // length % 4 != 0
    size_t st = length - rmdr;
    Ipp32u tmp = chardata[st] & 0xFF;
    for (size_t j = 1; j < rmdr; ++j)
      tmp += (chardata[j + st] & 0xFF) << (8 * j);
    *(data32 + new_length - 1) = tmp;
  }

  return BigNumber(data32, new_length);
}

py::bytes BN2bytes(const BigNumber& bn) {
  int bnBitLen;
  Ipp32u* bnData = nullptr;
  ippsRef_BN(nullptr, &bnBitLen, &bnData, bn);
  int length = BITSIZE_WORD(bnBitLen) * 4;
  unsigned char* bytesData = reinterpret_cast<unsigned char*>(bnData);
  std::string str(reinterpret_cast<char*>(bytesData), length);
  return py::bytes(str);
}
py::bytes BN2bytes(const std::shared_ptr<BigNumber>& bn) {
  int bnBitLen;
  Ipp32u* bnData = nullptr;
  ippsRef_BN(nullptr, &bnBitLen, &bnData, *bn);
  int length = BITSIZE_WORD(bnBitLen) * 4;
  unsigned char* bytesData = reinterpret_cast<unsigned char*>(bnData);
  std::string str(reinterpret_cast<char*>(bytesData), length);
  return py::bytes(str);
}
};  // namespace ipclPythonUtils
