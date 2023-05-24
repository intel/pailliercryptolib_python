// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <memory>
#include <vector>

#include "include/baseconverter.hpp"
#include "include/ipcl_bindings.hpp"

namespace nb = nanobind;

void def_ipclPublicKey(nb::module_& m) {
  // Paillier publickey module
  nb::class_<ipcl::PublicKey>(m, "ipclPublicKey")
      .def(
          "__init__",
          [](ipcl::PublicKey* t, const BigNumber& n) {
            new (t) ipcl::PublicKey(n, 1024);
          },
          "ipclPublicKey constructor")
      .def(
          "__init__",
          [](ipcl::PublicKey* t, const BigNumber& n, int bits) {
            new (t) ipcl::PublicKey(n, bits);
          },
          "ipclPublicKey constructor")
      .def(
          "__init__",
          [](ipcl::PublicKey* t, const BigNumber& n, int bits,
             bool enable_DJN) { new (t) ipcl::PublicKey(n, bits, enable_DJN); },
          "ipclPublicKey constructor")
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
      .def_prop_ro("n", &ipcl::PublicKey::getN,
                   "ipclPublicKey n in ipclBigNumber")
      .def_prop_ro("length", &ipcl::PublicKey::getBits, "ipclPublicKey length")
      .def_prop_ro("nsquare", &ipcl::PublicKey::getNSQ,
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
            return ct.getTexts();
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
             return ret;
           })
      .def("__getstate__",
           [](const ipcl::PublicKey& self) {
             return ipclPythonUtils::getTupleIpclPubKey(self);
           })
      .def("__setstate__", [](ipcl::PublicKey& self, nb::tuple t) {
        new (&self) ipcl::PublicKey(ipclPythonUtils::setIpclPubKey(t));
      });
}

void def_ipclPrivateKey(nb::module_& m) {
  nb::class_<ipcl::PrivateKey>(m, "ipclPrivateKey")
      .def(
          "__init__",
          [](ipcl::PrivateKey* t, const ipcl::PublicKey& pubkey,
             const BigNumber& p,
             const BigNumber& q) { new (t) ipcl::PrivateKey(pubkey, p, q); },
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
      .def_prop_ro("n", &ipcl::PrivateKey::getN, "get ipclPublicKey n property")
      .def_prop_ro("p", &ipcl::PrivateKey::getP,
                   "get ipclPrivateKey p property")
      .def_prop_ro("q", &ipcl::PrivateKey::getQ,
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
            return pt.getTexts();
          },
          "decrypt ipcl::CipherText into container of ipcl::PlainText")
      .def("__getstate__",
           [](const ipcl::PrivateKey& self) {
             std::shared_ptr<BigNumber> n = self.getN();
             auto _n = ipclPythonUtils::BN2bytes(n);
             std::shared_ptr<BigNumber> p = self.getP();
             auto _p = ipclPythonUtils::BN2bytes(p);
             std::shared_ptr<BigNumber> q = self.getQ();
             auto _q = ipclPythonUtils::BN2bytes(q);

             return nb::make_tuple(_n, _p, _q);
           })
      .def("__setstate__", [](ipcl::PrivateKey& self, nb::tuple t) {
        nb::bytes l_n = t[0];
        BigNumber n = ipclPythonUtils::pyByte2BN(l_n);
        nb::bytes l_p = t[1];
        BigNumber p = ipclPythonUtils::pyByte2BN(l_p);
        nb::bytes l_q = t[2];
        BigNumber q = ipclPythonUtils::pyByte2BN(l_q);
        new (&self) ipcl::PrivateKey(n, p, q);
      });
}

void def_ipclPlainText(nb::module_& m) {
  // ipcl::PlainText
  nb::class_<ipcl::PlainText, ipcl::BaseText>(m, "ipclPlainText")
      .def(nb::init<const uint32_t&>(), "ipclPlainText constructor")
      .def(nb::init<const BigNumber&>(), "ipclPlainText constructor")
      .def(nb::init<const ipcl::PlainText&>(), "ipclPlainText constructor")
      .def(
          "__init__",
          [](ipcl::PlainText* t, nb::list data) {
            std::vector<BigNumber> pData =
                nb::cast<std::vector<BigNumber>>(data);
            new (t) ipcl::PlainText(pData);
          },
          "ipclPlainText constructor with list of BigNumbers")
      .def(
          "__init__",
          [](ipcl::PlainText* t, nb::ndarray<Ipp32u> data) {
            size_t length = data.shape(0);
            Ipp32u* _data = static_cast<Ipp32u*>(data.data());
            std::vector<Ipp32u> pData(_data, _data + length);
            delete[] _data;
            new (t) ipcl::PlainText(pData);
          },
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
            return vec;
          },
          "Get element in little endian vector")
      .def("getElementHex", &ipcl::PlainText::getElementHex,
           "Get element in hexadecimal string")
      .def(
          "getTexts",
          [](const ipcl::PlainText& self) {
            std::vector<BigNumber> vec = self.getTexts();
            return vec;
          },
          "Get container in BigNumber vector")
      .def("getSize", &ipcl::PlainText::getSize, "Get size of container")
      .def("__getstate__",
           [](const ipcl::PlainText& self) {
             std::vector<BigNumber> vec = self.getTexts();
             size_t length = self.getSize();
             nb::list l_bn;
             for (auto it : vec) l_bn.append(ipclPythonUtils::BN2bytes(it));
             return nb::make_tuple(length, l_bn);
           })
      .def("__setstate__", [](ipcl::PlainText& self, const nb::tuple& t) {
        size_t length = static_cast<size_t>(nb::cast<int>(t[0]));
        std::vector<BigNumber> vec(length);
        nb::list l_lbn = t[1];
        for (size_t i = 0; i < length; ++i) {
          nb::bytes lbn = l_lbn[i];
          vec[i] = ipclPythonUtils::pyByte2BN(lbn);
        }
        new (&self) ipcl::PlainText(vec);
      });
}

void def_ipclCipherText(nb::module_& m) {
  // ipcl::CipherText
  nb::class_<ipcl::CipherText, ipcl::BaseText>(m, "ipclCipherText")
      .def(nb::init<const ipcl::PublicKey&, const uint32_t&>(),
           "ipclCipherText constructor")
      .def(nb::init<const ipcl::PublicKey&, const BigNumber&>(),
           "ipclCipherText constructor")
      .def(
          "__init__",
          [](ipcl::CipherText* t, const ipcl::PublicKey& pk, nb::list data) {
            std::vector<BigNumber> pData =
                nb::cast<std::vector<BigNumber>>(data);
            new (t) ipcl::CipherText(pk, pData);
          },
          "ipclCipherText constructor with list of BigNumbers")
      .def(
          "__init__",
          [](ipcl::CipherText* t, const ipcl::PublicKey& pk,
             nb::ndarray<Ipp32u> data) {
            size_t length = data.shape(0);
            Ipp32u* _data = static_cast<Ipp32u*>(data.data());
            std::vector<Ipp32u> pData(_data, _data + length);
            delete[] _data;
            new (t) ipcl::CipherText(pk, pData);
          },
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
            return vec;
          },
          "Get element in little endian vector")
      .def_prop_ro("public_key",
                   [](const ipcl::CipherText& self) {
                     std::shared_ptr<ipcl::PublicKey> pk = self.getPubKey();
                     return pk;
                   })
      .def("getElementHex", &ipcl::CipherText::getElementHex,
           "Get element in hexadecimal string")
      .def(
          "getTexts",
          [](const ipcl::CipherText& self) {
            std::vector<BigNumber> vec = self.getTexts();
            return vec;
          },
          "Get container in BigNumber vector")
      .def("getSize", &ipcl::CipherText::getSize, "Get size of container")
      .def("__getstate__",
           [](const ipcl::CipherText& self) {
             std::vector<BigNumber> vec = self.getTexts();
             size_t length = self.getSize();
             nb::list l_bn;
             for (auto it : vec) l_bn.append(ipclPythonUtils::BN2bytes(it));
             std::shared_ptr<ipcl::PublicKey> _pk = self.getPubKey();
             nb::tuple t_pubkey = ipclPythonUtils::getTupleIpclPubKey(*_pk);
             return nb::make_tuple(length, l_bn, t_pubkey);
           })
      .def("__setstate__", [](ipcl::CipherText& self, const nb::tuple& t) {
        size_t length = static_cast<size_t>(nb::cast<int>(t[0]));
        std::vector<BigNumber> vec(length);
        nb::list l_lbn = t[1];
        for (size_t i = 0; i < length; ++i) {
          nb::bytes lbn = l_lbn[i];
          vec[i] = ipclPythonUtils::pyByte2BN(lbn);
        }
        nb::tuple t_pubkey = t[2];
        ipcl::PublicKey pubkey = ipclPythonUtils::setIpclPubKey(t_pubkey);
        new (&self) ipcl::CipherText(pubkey, vec);
      });
}

void def_BigNumber(nb::module_& m) {
  nb::class_<BigNumber>(m, "ipclBigNumber")
      .def(nb::init<BigNumber&>(), "ipclBigNumber constructor")
      .def(
          "__init__",
          [](BigNumber* t, Ipp32u data) { new (t) BigNumber(data); },
          "ipclBigNumber constructor")
      .def(
          "__init__",
          [](BigNumber* t, const nb::list& data) {
            size_t length = data.size();
            std::vector<Ipp32u> pData = nb::cast<std::vector<Ipp32u>>(data);
            new (t) BigNumber(pData.data(), pData.size());
          },
          "ipclBigNumber constructor with list of integers - little endian "
          "format")
      .def(
          "__init__",
          [](BigNumber* t, const nb::ndarray<Ipp32u>& data) {
            ssize_t length = data.shape(0);
            Ipp32u* pData = const_cast<Ipp32u*>(data.data());
            new (t) BigNumber(pData, length);
          },
          "ipclBigNumber constructor with array of integers - little endian "
          "format")
      .def("__init__",
           [](BigNumber* t, const nb::bytes& data) {
             new (t) BigNumber(ipclPythonUtils::pyByte2BN(data));
           })
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
            nb::list l_dt;
            for (int i = 0; i < length; i++) l_dt.append(bnData[i]);
            return nb::make_tuple(length, l_dt);
          },
          "return ipclBigNumber in size and list of 32bit unsigned integers")
      .def(
          "to_bytes",
          [](BigNumber const& self) { return ipclPythonUtils::BN2bytes(self); })
      .def_prop_ro_static("Zero",
                          [](const nb::object&) { return BigNumber::Zero(); })
      .def_prop_ro_static("One",
                          [](const nb::object&) { return BigNumber::One(); })
      .def_prop_ro_static("Two",
                          [](const nb::object&) { return BigNumber::Two(); })
      .def("__getstate__",
           [](const BigNumber& self) {
             auto btl = ipclPythonUtils::BN2bytes(self);
             return nb::make_tuple(btl);
           })
      .def("__setstate__", [](BigNumber& self, const nb::tuple t) {
        nb::bytes l_dt = t[0];
        new (&self) BigNumber(ipclPythonUtils::pyByte2BN(l_dt));
      });
}
