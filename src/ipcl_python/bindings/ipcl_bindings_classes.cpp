// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <memory>
#include <vector>

#include "include/baseconverter.hpp"
#include "include/ipcl_bindings.hpp"

namespace py = pybind11;

void def_ipclPublicKey(py::module& m) {
  // Paillier publickey module
  py::class_<ipcl::PublicKey, std::shared_ptr<ipcl::PublicKey>>(m,
                                                                "ipclPublicKey")
      .def(py::init([](const BigNumber& n) {
             return std::shared_ptr<ipcl::PublicKey>(
                 new ipcl::PublicKey(n, 1024));
           }),
           "ipclPublicKey constructor")
      .def(py::init([](const BigNumber& n, int bits) {
             return std::shared_ptr<ipcl::PublicKey>(
                 new ipcl::PublicKey(n, bits));
           }),
           "ipclPublicKey constructor")
      .def(py::init([](const BigNumber& n, int bits, bool enable_DJN) {
        std::shared_ptr<ipcl::PublicKey> ret =
            std::make_shared<ipcl::PublicKey>(new ipcl::PublicKey(n, bits));
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def("__repr__",
           [](const ipcl::PublicKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPublicKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const ipcl::PublicKey& self, const ipcl::PublicKey& other) {
             return self.getN() == other.getN();
           })
      .def("__hash__",
           [](const ipcl::PublicKey& self) {
             std::stringstream ss;
             ss << self.getN();
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("n", &ipcl::PublicKey::getN,
                             "ipclPublicKey n in ipclBigNumber")
      .def_property_readonly("length", &ipcl::PublicKey::getBits,
                             "ipclPublicKey length")
      .def_property_readonly("nsquare", &ipcl::PublicKey::getNSQ,
                             "square of ipclPublicKey n in ipclBigNumber")
      .def(
          "encrypt",  // encrypt plaintext
          [](const ipcl::PublicKey& self, const ipcl::PlainText& pt,
             bool make_secure) {
            ipcl::CipherText ct = self.encrypt(pt, make_secure);
            return ct;
          },
          "encrypt ipcl::PlainText and returns ipcl::CipherText")
      .def(
          "encrypt_tolist",  // encrypt plaintext and return container of
                             // Ciphertext
          [](const ipcl::PublicKey& self, const ipcl::PlainText& pt,
             bool make_secure) {
            ipcl::CipherText ct = self.encrypt(pt, make_secure);
            py::list l_container = py::cast(ct.getTexts());
            return l_container;
          },
          "encrypt ipcl::PlainText and returns container of ipcl::CipherText")
      .def("apply_obfuscator",  // ciphertext obfuscator
           [](const ipcl::PublicKey& self, const BigNumber& ct) {
             std::vector<BigNumber> ret(1, ct);
             self.applyObfuscator(ret);
             return ret[0];
           })
      .def("apply_obfuscator",  // overloaded ciphertext obfuscator
           [](const ipcl::PublicKey& self, const ipcl::CipherText& ct) {
             std::vector<BigNumber> ret = ct.getTexts();
             self.applyObfuscator(ret);
             py::list l_ret = py::cast(ret);
             return l_ret;
           })
      .def(py::pickle(
          [](const ipcl::PublicKey& self) {  // __getstate__
            return ipclPythonUtils::getTupleIpclPubKey(self);
          },
          [](py::tuple t) {  // __setstate__
            return ipclPythonUtils::setIpclPubKey(t);
          }));
}

void def_ipclPrivateKey(py::module& m) {
  py::class_<ipcl::PrivateKey, std::shared_ptr<ipcl::PrivateKey>>(
      m, "ipclPrivateKey")
      .def(py::init([](const ipcl::PublicKey& pubkey, const BigNumber& p,
                       const BigNumber& q) {
             return std::shared_ptr<ipcl::PrivateKey>(
                 new ipcl::PrivateKey(pubkey, p, q));
           }),
           "ipclPrivateKey constructor")
      .def("__repr__",
           [](const ipcl::PrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPrivateKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const ipcl::PrivateKey& self, const ipcl::PrivateKey& other) {
             return self.getQ() == other.getQ();
           })
      .def("__hash__",
           [](const ipcl::PrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("n", &ipcl::PrivateKey::getN,
                             "get ipclPublicKey n property")
      .def_property_readonly("p", &ipcl::PrivateKey::getP,
                             "get ipclPrivateKey p property")
      .def_property_readonly("q", &ipcl::PrivateKey::getQ,
                             "get ipclPrivateKey q property")
      .def(
          "decrypt",  // decrypt ipcl::CipherText
          [](ipcl::PrivateKey& self, const ipcl::CipherText& ct) {
            ipcl::PlainText pt = self.decrypt(ct);
            return pt;
          },
          "decrypt ipcl::CipherText into ipcl::PlainText")
      .def(
          "decrypt_tolist",  // decrypt ipcl::CipherText and return container
          [](ipcl::PrivateKey& self, const ipcl::CipherText& ct) {
            ipcl::PlainText pt = self.decrypt(ct);
            py::list l_container = py::cast(pt.getTexts());
            return l_container;
          },
          "decrypt ipcl::CipherText into container of ipcl::PlainText")
      .def(py::pickle(
          [](const ipcl::PrivateKey& self) {  // __getstate__
            BigNumber n = *(self.getN());
            auto _n = ipclPythonUtils::BN2bytes(n);
            BigNumber p = *(self.getP());
            auto _p = ipclPythonUtils::BN2bytes(p);
            BigNumber q = *(self.getQ());
            auto _q = ipclPythonUtils::BN2bytes(q);

            return py::make_tuple(_n, _p, _q);
          },
          [](py::tuple t) {  // __setstate__
            py::bytes l_n = t[0];
            BigNumber n = ipclPythonUtils::pyByte2BN(l_n);
            py::bytes l_p = t[1];
            BigNumber p = ipclPythonUtils::pyByte2BN(l_p);
            py::bytes l_q = t[2];
            BigNumber q = ipclPythonUtils::pyByte2BN(l_q);
            return std::unique_ptr<ipcl::PrivateKey>(
                new ipcl::PrivateKey(n, p, q));
          }));
}

void def_ipclPlainText(py::module& m) {
  // ipcl::PlainText
  py::class_<ipcl::PlainText>(m, "ipclPlainText")
      .def(py::init<const uint32_t&>(), "ipclPlainText constructor")
      .def(py::init<const BigNumber&>(), "ipclPlainText constructor")
      .def(py::init<const ipcl::PlainText&>(), "ipclPlainText constructor")
      .def(py::init([](py::list data) {
             std::vector<BigNumber> pData =
                 py::cast<std::vector<BigNumber>>(data);
             return ipcl::PlainText(pData);
           }),
           "ipclPlainText constructor with list of BigNumbers")
      .def(py::init([](py::array_t<Ipp32u> data) {
             py::buffer_info buffer_info = data.request();
             size_t length = buffer_info.shape[0];
             Ipp32u* _data = static_cast<Ipp32u*>(buffer_info.ptr);
             std::vector<Ipp32u> pData(_data, _data + length);
             delete[] _data;
             return ipcl::PlainText(pData);
           }),
           "ipclPlainText constructor with numpy array of unsigned integers "
           "(32bit)")
      .def("__repr__",
           [](const ipcl::PlainText& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPlainText " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__str__",
           [](const ipcl::PlainText& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPlainText " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const ipcl::PlainText& self, const ipcl::PlainText& other) {
             if (self.getSize() != other.getSize())
               throw std::runtime_error("Size mismatch");
             size_t length = self.getSize();
             std::vector<BigNumber> selfText = self.getTexts();
             std::vector<BigNumber> otherText = other.getTexts();
             for (size_t i = 0; i < length; ++i)
               if (selfText[i] != otherText[i])
                 throw std::runtime_error("PlainText mismatch");

             return true;
           })
      .def("__getitem__", &ipcl::PlainText::getElement)
      .def("__len__", &ipcl::PlainText::getSize)
      .def("rotate", &ipcl::PlainText::rotate, "Rotate ipclPlainText container")
      .def(
          "getElementVec",
          [](const ipcl::PlainText& self, const size_t& n) {
            std::vector<uint32_t> vec = self.getElementVec(n);
            py::list l_vec = py::cast(vec);
            return l_vec;
          },
          "Get element in little endian vector")
      .def("getElementHex", &ipcl::PlainText::getElementHex,
           "Get element in hexadecimal string")
      .def(
          "getTexts",
          [](const ipcl::PlainText& self) {
            std::vector<BigNumber> vec = self.getTexts();
            py::list l_vec = py::cast(vec);
            return l_vec;
          },
          "Get container in BigNumber vector")
      .def("getSize", &ipcl::PlainText::getSize,
           "Get size of container")
      .def(py::pickle(
          [](const ipcl::PlainText& self) {  // __getstate__
            std::vector<BigNumber> vec = self.getTexts();
            size_t length = self.getSize();
            py::list l_bn;
            for (auto it : vec) l_bn.append(ipclPythonUtils::BN2bytes(it));
            return py::make_tuple(length, l_bn);
          },
          [](const py::tuple& t) {  // __setstate__
            size_t length = static_cast<size_t>(py::cast<int>(t[0]));
            std::vector<BigNumber> vec(length);
            py::list l_lbn = t[1];
            for (size_t i = 0; i < length; ++i) {
              py::bytes lbn = l_lbn[i];
              vec[i] = ipclPythonUtils::pyByte2BN(lbn);
            }
            return ipcl::PlainText(vec);
          }));
}

void def_ipclCipherText(py::module& m) {
  // ipcl::CipherText
  py::class_<ipcl::CipherText, std::shared_ptr<ipcl::CipherText>>(
      m, "ipclCipherText")
      .def(py::init<const ipcl::PublicKey&, const uint32_t&>(),
           "ipclCipherText constructor")
      .def(py::init<const ipcl::PublicKey&, const BigNumber&>(),
           "ipclCipherText constructor")
      .def(py::init([](const ipcl::PublicKey& pk, py::list data) {
             std::vector<BigNumber> pData =
                 py::cast<std::vector<BigNumber>>(data);
             return ipcl::CipherText(pk, pData);
           }),
           "ipclCipherText constructor with list of BigNumbers")
      .def(py::init([](const ipcl::PublicKey& pk, py::array_t<Ipp32u> data) {
             py::buffer_info buffer_info = data.request();
             size_t length = buffer_info.shape[0];
             Ipp32u* _data = static_cast<Ipp32u*>(buffer_info.ptr);
             std::vector<Ipp32u> pData(_data, _data + length);
             delete[] _data;
             return ipcl::CipherText(pk, pData);
           }),
           "ipclCipherText constructor with numpy array of unsigned integers "
           "(32bit)")
      .def("__repr__",
           [](const ipcl::CipherText& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclCipherText " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__str__",
           [](const ipcl::CipherText& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclCipherText " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__getitem__", &ipcl::CipherText::getElement)
      .def("__add__",
           [](const ipcl::CipherText& self, const ipcl::CipherText& other) {
             return self + other;
           })
      .def("__add__", [](const ipcl::CipherText& self,
                         const ipcl::PlainText& other) { return self + other; })
      .def("__mul__", [](const ipcl::CipherText& self,
                         const ipcl::PlainText& other) { return self * other; })
      .def("__len__", &ipcl::CipherText::getSize)
      .def("getCipherText", &ipcl::CipherText::getCipherText)
      .def("rotate", &ipcl::CipherText::rotate,
           "Rotate ipclCipherText container")
      .def(
          "getElementVec",
          [](const ipcl::CipherText& self, const size_t& n) {
            std::vector<uint32_t> vec = self.getElementVec(n);
            py::list l_vec = py::cast(vec);
            return l_vec;
          },
          "Get element in little endian vector")
      .def_property_readonly("public_key",
                             [](const ipcl::CipherText& self) {
                               std::shared_ptr<ipcl::PublicKey> pk =
                                   self.getPubKey();
                               return pk;
                             })
      .def("getElementHex", &ipcl::CipherText::getElementHex,
           "Get element in hexadecimal string")
      .def(
          "getTexts",
          [](const ipcl::CipherText& self) {
            std::vector<BigNumber> vec = self.getTexts();
            py::list l_vec = py::cast(vec);
            return l_vec;
          },
          "Get container in BigNumber vector")
      .def("getSize", &ipcl::CipherText::getSize,
           "Get size of container")
      .def(py::pickle(
          [](const ipcl::CipherText& self) {  // __getstate__
            std::vector<BigNumber> vec = self.getTexts();
            size_t length = self.getSize();
            py::list l_bn;
            for (auto it : vec) l_bn.append(ipclPythonUtils::BN2bytes(it));
            std::shared_ptr<ipcl::PublicKey> _pk = self.getPubKey();
            py::tuple t_pubkey = ipclPythonUtils::getTupleIpclPubKey(*_pk);
            return py::make_tuple(length, l_bn, t_pubkey);
          },
          [](const py::tuple& t) {  // __setstate__
            size_t length = static_cast<size_t>(py::cast<int>(t[0]));
            std::vector<BigNumber> vec(length);
            py::list l_lbn = t[1];
            for (size_t i = 0; i < length; ++i) {
              py::bytes lbn = l_lbn[i];
              vec[i] = ipclPythonUtils::pyByte2BN(lbn);
            }
            py::tuple t_pubkey = t[2];
            ipcl::PublicKey pubkey = ipclPythonUtils::setIpclPubKey(t_pubkey);
            return ipcl::CipherText(pubkey, vec);
          }));
}

void def_BigNumber(py::module& m) {
  py::class_<BigNumber, std::shared_ptr<BigNumber>>(m, "ipclBigNumber")
      .def(py::init<BigNumber&>(), "ipclBigNumber constructor")
      .def(py::init(
               [](Ipp32u data) { return std::make_shared<BigNumber>(data); }),
           "ipclBigNumber constructor")
      .def(py::init([](const py::list& data) {
             size_t length = data.size();
             std::vector<Ipp32u> pData = py::cast<std::vector<Ipp32u>>(data);
             return std::shared_ptr<BigNumber>(
                 new BigNumber(pData.data(), pData.size()));
           }),
           "ipclBigNumber constructor with list of integers - little endian "
           "format")
      .def(py::init([](const py::array_t<Ipp32u>& data) {
             py::buffer_info buffer_info = data.request();

             Ipp32u* pData = static_cast<Ipp32u*>(buffer_info.ptr);
             std::vector<ssize_t> shape = buffer_info.shape;
             return std::shared_ptr<BigNumber>(new BigNumber(pData, shape[0]));
           }),
           "ipclBigNumber constructor with array of integers - little endian "
           "format")
      .def(py::init([](const py::bytes& data) {
        return std::shared_ptr<BigNumber>(
            new BigNumber(ipclPythonUtils::pyByte2BN(data)));
      }))
      .def("__repr__",
           [](BigNumber const& self) {
             std::stringstream ss_hash;
             ss_hash << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss_hash.str());
             std::string s_dec = baseconverter::BN2dec(self);
             return std::string("<BigNumber " +
                                std::to_string(hashcode).substr(0, 10) +
                                " val: " + s_dec + ">");
           })
      .def("__str__",
           [](BigNumber const& self) {
             std::string s_dec = baseconverter::BN2dec(self);
             return s_dec;
           })
      .def("__getitem__",
           [](BigNumber const& self, size_t n) {
             int bnBitLen;
             Ipp32u* bnData;
             ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
             int length = BITSIZE_WORD(bnBitLen);
             if (n >= length)
               throw std::out_of_range("Index is larger than size: " +
                                       std::to_string(length));
             return bnData[n];
           })
      .def("__eq__", [](BigNumber const& self,
                        BigNumber const& other) { return self == other; })
      .def("__ne__", [](BigNumber const& self,
                        BigNumber const& other) { return self != other; })
      .def("__add__", [](BigNumber const& self,
                         BigNumber const& other) { return self + other; })
      .def("__sub__", [](BigNumber const& self,
                         BigNumber const& other) { return self - other; })
      .def("__iadd__",
           [](BigNumber& self, BigNumber const& other) {
             self += other;
             return self;
           })
      .def("__mul__", [](BigNumber const& self,
                         BigNumber const& other) { return self * other; })
      .def("__mul__",
           [](BigNumber const& self, Ipp32u other) { return self * other; })
      .def("__lt__", [](BigNumber const& self,
                        BigNumber const& other) { return self < other; })
      .def("__le__", [](BigNumber const& self,
                        BigNumber const& other) { return self <= other; })
      .def("__gt__", [](BigNumber const& self,
                        BigNumber const& other) { return self > other; })
      .def("__ge__", [](BigNumber const& self,
                        BigNumber const& other) { return self >= other; })
      .def("DwordSize", &BigNumber::DwordSize)
      .def("BitSize", &BigNumber::BitSize)
      .def(
          "data",
          [](BigNumber const& self) {
            int bnBitLen;
            Ipp32u* bnData = nullptr;
            ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
            int length = BITSIZE_WORD(bnBitLen);
            py::list l_dt;
            for (int i = 0; i < length; i++) l_dt.append(bnData[i]);
            return py::make_tuple(length, l_dt);
          },
          "return ipclBigNumber in size and list of 32bit unsigned integers")
      .def(
          "to_bytes",
          [](BigNumber const& self) { return ipclPythonUtils::BN2bytes(self); })
      .def_property_readonly_static(
          "Zero", [](const py::object&) { return BigNumber::Zero(); })
      .def_property_readonly_static(
          "One", [](const py::object&) { return BigNumber::One(); })
      .def_property_readonly_static(
          "Two", [](const py::object&) { return BigNumber::Two(); })
      .def(py::pickle(
          [](const BigNumber& self) {  // __getstate__
            auto btl = ipclPythonUtils::BN2bytes(self);
            return py::make_tuple(btl);
          },
          [](py::tuple t) {  // __setstate__
            py::bytes l_dt = t[0];
            return std::shared_ptr<BigNumber>(
                new BigNumber(ipclPythonUtils::pyByte2BN(l_dt)));
          }));
}
