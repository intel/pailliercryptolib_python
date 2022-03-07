// Copyright (C) 2021-2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <memory>
#include <vector>

#include "include/ipcl_bindings.h"

namespace py = pybind11;

void def_ipclPublicKey(py::module& m) {
  // Paillier publickey module
  py::class_<ipcl::PaillierPublicKey>(m, "ipclPublicKey")
      .def(py::init([](const ipcl::BigNumber& n) {
             ipcl::PaillierPublicKey* ret =
                 new ipcl::PaillierPublicKey(n, 1024);
             return ret;
           }),
           R"ipclPublicKey(
        ipclPublicKey constructor

        Parameters:
          n: Public key value n in ipcl::BigNumber format
      )ipclPublicKey")
      .def(py::init([](const ipcl::BigNumber& n, bool enable_DJN) {
        ipcl::PaillierPublicKey* ret = new ipcl::PaillierPublicKey(n, 1024);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def(py::init([](const ipcl::BigNumber& n, int bits) {
        ipcl::PaillierPublicKey* ret = new ipcl::PaillierPublicKey(n, bits);
        return ret;
      }))
      .def(py::init([](const ipcl::BigNumber& n, int bits, bool enable_DJN) {
        ipcl::PaillierPublicKey* ret = new ipcl::PaillierPublicKey(n, bits);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def("__repr__",
           [](const ipcl::PaillierPublicKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPublicKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const ipcl::PaillierPublicKey& self,
              const ipcl::PaillierPublicKey& other) {
             return self.getN() == other.getN();
           })
      .def("__hash__",
           [](const ipcl::PaillierPublicKey& self) {
             std::stringstream ss;
             ss << self.getN();
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("n", &ipcl::PaillierPublicKey::getN)
      .def_property_readonly("length", &ipcl::PaillierPublicKey::getBits)
      .def_property_readonly("nsquare", &ipcl::PaillierPublicKey::getNSQ)
      .def("raw_encrypt",  // encrypt single BigNumber
           [](ipcl::PaillierPublicKey& self, ipcl::BigNumber& bn,
              bool make_secure) {
             std::vector<ipcl::BigNumber> pt{bn, 0, 0, 0, 0, 0, 0, 0};
             std::vector<ipcl::BigNumber> ct(8);

             self.encrypt(ct, pt);
             return ct[0];
           })
      .def("raw_encrypt_buff8",  // encrypt 8 pack list of BigNumbers
           [](ipcl::PaillierPublicKey& self, py::list vals, bool make_secure) {
             size_t length = vals.size();
             if (length > 8)
               throw std::out_of_range("Vals size is larger than 8");
             std::vector<ipcl::BigNumber> pData =
                 py::cast<std::vector<ipcl::BigNumber>>(vals);
             if (length < 8) pData.resize(8, ipcl::BigNumber::Zero());

             std::vector<ipcl::BigNumber> ct(8);
             self.encrypt(ct, pData, make_secure);
             py::list l_ct = py::cast(ct);
             return l_ct;
           })
      .def("raw_encrypt_buff8",  // encrypt 8 pack numpy array of BigNumbers
           [](ipcl::PaillierPublicKey& self, py::array vals, bool make_secure) {
             py::buffer_info buffer_info = vals.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("Value size is larger than 8");
             ipcl::BigNumber* data =
                 static_cast<ipcl::BigNumber*>(buffer_info.ptr);

             std::vector<ipcl::BigNumber> pData(data, data + length);
             if (length < 8) pData.resize(8, ipcl::BigNumber::Zero());

             std::vector<ipcl::BigNumber> ct(8);
             self.encrypt(ct, pData, make_secure);
             py::list l_ct = py::cast(ct);
             delete[] data;
             return l_ct;
           })
      .def("raw_encrypt_insecure",  // encrypt bn insecure, for plaintext
                                    // add/mul
           [](ipcl::PaillierPublicKey& self, ipcl::BigNumber& bn) {
             ipcl::BigNumber ct;
             self.encrypt(ct, bn);
             return ct;
           })
      .def("encrypt",
           [](ipcl::PaillierPublicKey& self, ipcl::BigNumber& val,
              bool make_secure) {
             std::vector<ipcl::BigNumber> pt(8);
             pt[0] = val;

             std::vector<ipcl::BigNumber> ct(8);
             self.encrypt(ct, pt, make_secure);
             ipcl::PaillierEncryptedNumber ret(&self, ct[0]);
             return ret;
           })
      .def("encrypt_buff8",  // encrypt 8 pack list to single
                             // PaillierEncryptedNumber
           [](ipcl::PaillierPublicKey& self, py::list vals, bool make_secure) {
             size_t length = vals.size();
             if (length > 8)
               throw std::out_of_range("List size is larger than 8");
             std::vector<ipcl::BigNumber> pData =
                 py::cast<std::vector<ipcl::BigNumber>>(vals);
             if (length < 8) pData.resize(8, ipcl::BigNumber::Zero());

             std::vector<ipcl::BigNumber> ct(8);
             self.encrypt(ct, pData, make_secure);

             ipcl::PaillierEncryptedNumber ret(&self, ct, length);
             return ret;
           })
      .def("encrypt_buff8",  // encrypt 8 pack array to single
                             // PaillierEncryptedNumber
           [](ipcl::PaillierPublicKey& self, py::array vals, bool make_secure) {
             py::buffer_info buffer_info = vals.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("Array size is larger than 8");
             ipcl::BigNumber* data =
                 static_cast<ipcl::BigNumber*>(buffer_info.ptr);

             std::vector<ipcl::BigNumber> pData(data, data + length);
             if (length < 8) pData.resize(8, ipcl::BigNumber::Zero());
             std::vector<ipcl::BigNumber> ct(8);
             self.encrypt(ct, pData, make_secure);

             ipcl::PaillierEncryptedNumber ret(&self, ct, length);
             return ret;
           })
      .def(py::pickle(
          [](const ipcl::PaillierPublicKey& self) {  // __getstate__
            ipcl::BigNumber bn = self.getN();
            auto lbn = py_ippUtils::BN2pylist(bn);
            int bits = self.getBits();
            return py::make_tuple(lbn.second, bits);
          },
          [](py::tuple t) {  // __setstate__
            py::list l_bn = t[0];
            ipcl::BigNumber n = py_ippUtils::pylist2BN(l_bn);
            int n_length = py::cast<int>(t[1]);
            ipcl::PaillierPublicKey* pk =
                new ipcl::PaillierPublicKey(n, n_length);
            return pk;
          }));
}

void def_ipclPrivateKey(py::module& m) {
  py::class_<ipcl::PaillierPrivateKey>(m, "ipclPrivateKey")
      .def(py::init([](ipcl::PaillierPublicKey* pubkey,
                       const ipcl::BigNumber& p, const ipcl::BigNumber& q) {
        return std::unique_ptr<ipcl::PaillierPrivateKey>(
            new ipcl::PaillierPrivateKey(pubkey, p, q));
      }))
      .def("__repr__",
           [](const ipcl::PaillierPrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPrivateKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const ipcl::PaillierPrivateKey& self,
              const ipcl::PaillierPrivateKey& other) {
             return self.getQ() == other.getQ();
           })
      .def("__hash__",
           [](const ipcl::PaillierPrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("public_key", &ipcl::PaillierPrivateKey::getPubKey)
      .def_property_readonly("p", &ipcl::PaillierPrivateKey::getP)
      .def_property_readonly("q", &ipcl::PaillierPrivateKey::getQ)
      .def("decrypt",
           [](ipcl::PaillierPrivateKey& self,
              const ipcl::PaillierEncryptedNumber& value) {
             std::vector<ipcl::BigNumber> tmp(8);
             tmp[0] = value.getBN();
             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             return dt[0];
           })
      .def("decrypt",  //  decrypt packed PaillierEncryptedNumber
           [](ipcl::PaillierPrivateKey& self,
              const ipcl::PaillierEncryptedNumber& value, int sz) {
             std::vector<ipcl::BigNumber> this_bn = value.getArrayBN();
             std::vector<ipcl::BigNumber> pt(8);
             self.decrypt(pt, this_bn);
             if (sz < pt.size()) pt.resize(sz);

             py::list l_pt = py::cast(pt);
             return l_pt;
           })
      .def("decrypt_buff8",  // decrypt list of PaillierEncryptedNumbers
           [](ipcl::PaillierPrivateKey& self, const py::list& vals) {
             size_t length = vals.size();
             if (length > 8)
               throw std::out_of_range("vals size is larger than 8");
             std::vector<ipcl::BigNumber> tmp(8);
             for (int i = 0; i < length; i++)
               tmp[i] = vals[i].cast<ipcl::PaillierEncryptedNumber>().getBN();
             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             py::list l_dt = py::cast(dt);
             return l_dt;
           })
      .def("decrypt_buff8",  // decrypt array of PaillierEncryptedNumbers
           [](ipcl::PaillierPrivateKey& self, const py::array& vals) {
             py::buffer_info buffer_info = vals.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("vals size is larger than 8");
             ipcl::PaillierEncryptedNumber* data =
                 static_cast<ipcl::PaillierEncryptedNumber*>(buffer_info.ptr);
             std::vector<ipcl::BigNumber> tmp(8);
             for (int i = 0; i < length; i++) tmp[i] = data[i].getBN();
             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             py::list l_dt = py::cast(dt);
             return l_dt;
           })
      .def("raw_decrypt",  // decrypt BigNumber
           [](ipcl::PaillierPrivateKey& self, const ipcl::BigNumber& value) {
             std::vector<ipcl::BigNumber> tmp(8);
             tmp[0] = value;
             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             return dt[0];
           })
      .def("raw_decrypt_buff8",  // decrypt list of BigNumbers
           [](ipcl::PaillierPrivateKey& self, const py::list& vals) {
             size_t length = vals.size();
             if (length > 8)
               throw std::out_of_range("vals size is larger than 8");

             std::vector<ipcl::BigNumber> tmp;
             try {
               tmp = py::cast<std::vector<ipcl::BigNumber>>(vals);
               if (length < 8) tmp.resize(8, ipcl::BigNumber::Zero());
             } catch (int e) {
               throw std::invalid_argument("vals is not list of BigNumber");
             }

             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(dt[i]);
             return l_dt;
           })
      .def("raw_decrypt_buff8",  // decrypt array of BigNumbers
           [](ipcl::PaillierPrivateKey& self, const py::array& vals) {
             py::buffer_info buffer_info = vals.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("vals size is larger than 8");
             std::vector<ipcl::BigNumber> tmp;
             try {
               ipcl::BigNumber* data =
                   static_cast<ipcl::BigNumber*>(buffer_info.ptr);
               tmp.assign(data, data + length);
               if (length < 8) tmp.resize(8, ipcl::BigNumber::Zero());
             } catch (int e) {
               throw std::invalid_argument("vals is not an array of BigNumber");
             }

             std::vector<ipcl::BigNumber> dt(8);
             self.decrypt(dt, tmp);
             py::list l_dt = py::cast(dt);
             return l_dt;
           })
      .def(py::pickle(
          [](const ipcl::PaillierPrivateKey& self) {  // __getstate__
            const ipcl::PaillierPublicKey* pub = self.getPubKey();
            ipcl::BigNumber pubkeyN = pub->getN();
            auto _pubkeyN = py_ippUtils::BN2pylist(pubkeyN);
            int bits = pub->getBits();

            ipcl::BigNumber p = self.getP();
            auto _p = py_ippUtils::BN2pylist(p);
            ipcl::BigNumber q = self.getQ();
            auto _q = py_ippUtils::BN2pylist(q);

            return py::make_tuple(_pubkeyN.second, bits, _p.second, _q.second);
          },
          [](py::tuple t) {  // __setstate__
            py::list l_pubkeyN = t[0];
            ipcl::BigNumber pubkeyN = py_ippUtils::pylist2BN(l_pubkeyN);
            int bits = py::cast<int>(t[1]);
            ipcl::PaillierPublicKey* pub =
                new ipcl::PaillierPublicKey(pubkeyN, bits);

            py::list l_p = t[2];
            ipcl::BigNumber p = py_ippUtils::pylist2BN(l_p);
            py::list l_q = t[3];
            ipcl::BigNumber q = py_ippUtils::pylist2BN(l_q);
            ipcl::PaillierPrivateKey* pk =
                new ipcl::PaillierPrivateKey(pub, p, q);
            return pk;
          }));
}

void def_ipclEncryptedNumber(py::module& m) {
  // PaillierEncryptedNumber
  py::class_<ipcl::PaillierEncryptedNumber>(m, "ipclEncryptedNumber")
      .def(py::init<ipcl::PaillierPublicKey*, const ipcl::BigNumber>())
      .def(py::init<ipcl::PaillierPublicKey*, const uint32_t*>())
      .def(py::init([](ipcl::PaillierPublicKey* pubkey, const py::list vals) {
        size_t length = vals.size();
        if (length > 8) throw std::out_of_range("List size is larger than 8");
        std::vector<ipcl::BigNumber> pData =
            py::cast<std::vector<ipcl::BigNumber>>(vals);
        if (length < 8) pData.resize(8, ipcl::BigNumber::Zero());
        return ipcl::PaillierEncryptedNumber(pubkey, pData);
      }))
      .def("__repr__",
           [](const ipcl::PaillierEncryptedNumber& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclEncryptedNumber " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__str__",
           [](const ipcl::PaillierEncryptedNumber& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclEncryptedNumber " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("public_key", &ipcl::PaillierEncryptedNumber::getPK)
      .def("__add__",
           [](ipcl::PaillierEncryptedNumber const& self,
              ipcl::PaillierEncryptedNumber const& other) {
             return self + other;
           })
      .def("__mul__",
           [](ipcl::PaillierEncryptedNumber const& self,
              ipcl::PaillierEncryptedNumber const& other) {
             return self * other;
           })
      .def("__mul__", [](ipcl::PaillierEncryptedNumber const& self,
                         ipcl::BigNumber& other) { return self * other; })
      .def("rotate", &ipcl::PaillierEncryptedNumber::rotate)
      .def("isSingle", &ipcl::PaillierEncryptedNumber::isSingle)
      .def("__len__", &ipcl::PaillierEncryptedNumber::getLength)
      .def("getBN", &ipcl::PaillierEncryptedNumber::getBN)
      .def("getBN",
           [](ipcl::PaillierEncryptedNumber const& self) {
             return self.getBN();
           })
      .def("getAllBN",
           [](ipcl::PaillierEncryptedNumber const& self) {
             std::vector<ipcl::BigNumber> bn = self.getArrayBN();
             py::list l_bn = py::cast(bn);
             return l_bn;
           })
      .def(py::pickle(
          [](const ipcl::PaillierEncryptedNumber& self) {  // __getstate__
            ipcl::PaillierPublicKey pub = self.getPK();
            auto lpubn = py_ippUtils::BN2pylist(pub.getN());

            int bits = pub.getBits();

            std::vector<ipcl::BigNumber> bn = self.getArrayBN();
            size_t length = self.getLength();

            py::list l_bn;
            for (size_t i = 0; i < length; ++i) {
              auto lbn = py_ippUtils::BN2pylist(bn[i]);
              l_bn.append(lbn.second);
            }

            return py::make_tuple(lpubn.second, bits, length, l_bn);
          },
          [](py::tuple t) {  // __setstate__
            py::list l_pubn = t[0];
            ipcl::BigNumber pubn = py_ippUtils::pylist2BN(l_pubn);
            int bits = py::cast<int>(t[1]);
            ipcl::PaillierPublicKey* pub =
                new ipcl::PaillierPublicKey(pubn, bits);

            int length = py::cast<int>(t[2]);
            py::list l_bn = t[3];
            if (length == 1) {
              py::list lbn = l_bn[0];
              ipcl::BigNumber bn = py_ippUtils::pylist2BN(lbn);
              return std::make_unique<ipcl::PaillierEncryptedNumber>(pub, bn);
            }

            std::vector<ipcl::BigNumber> bn(8);
            for (size_t i = 0; i < length; ++i) {
              py::list lbn = l_bn[i];
              bn[i] = py_ippUtils::pylist2BN(lbn);
            }
            return std::make_unique<ipcl::PaillierEncryptedNumber>(pub, bn);
          }));
}

void def_BigNumber(py::module& m) {
  py::class_<ipcl::BigNumber>(m, "ipclBigNumber")
      .def(py::init<ipcl::BigNumber&>())
      .def(py::init([](unsigned int obj) {
        return std::make_unique<ipcl::BigNumber>(obj);
      }))
      .def(py::init([](py::list data) {
        size_t length = data.size();
        unsigned int* pData = new unsigned int[length];
        for (int i = 0; i < length; i++) {
          pData[i] = data[i].cast<unsigned int>();
        }
        return std::unique_ptr<ipcl::BigNumber>(
            new ipcl::BigNumber(pData, length));
      }))
      .def(py::init([](py::array_t<unsigned int> data) {
        py::buffer_info buffer_info = data.request();

        unsigned int* pData = static_cast<unsigned int*>(buffer_info.ptr);
        std::vector<ssize_t> shape = buffer_info.shape;
        return std::unique_ptr<ipcl::BigNumber>(
            new ipcl::BigNumber(pData, shape[0]));
      }))
      .def("__repr__",
           [](ipcl::BigNumber const& self) {
             std::stringstream ss_hash;
             ss_hash << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss_hash.str());
             std::string s_dec = baseconverter::BN2dec(self);
             return std::string("<BigNumber " +
                                std::to_string(hashcode).substr(0, 10) +
                                " val: " + s_dec + ">");
           })
      .def("__str__",
           [](ipcl::BigNumber const& self) {
             std::string s_dec = baseconverter::BN2dec(self);
             return s_dec;
           })
      .def("__getitem__",
           [](ipcl::BigNumber const& self, unsigned int n) {
             int bnBitLen;
             Ipp32u* bnData;
             ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
             int length = ipcl::BITSIZE_WORD(bnBitLen);
             if (n >= length)
               throw std::out_of_range("Index is larger than size: " +
                                       std::to_string(length));
             return bnData[n];
           })
      .def("__eq__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self == other; })
      .def("__ne__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self != other; })
      .def("__add__", [](ipcl::BigNumber const& self,
                         ipcl::BigNumber const& other) { return self + other; })
      .def("__sub__", [](ipcl::BigNumber const& self,
                         ipcl::BigNumber const& other) { return self - other; })
      .def("__iadd__",
           [](ipcl::BigNumber& self, ipcl::BigNumber const& other) {
             self += other;
             return self;
           })
      .def("__lt__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self < other; })
      .def("__le__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self <= other; })
      .def("__gt__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self > other; })
      .def("__ge__", [](ipcl::BigNumber const& self,
                        ipcl::BigNumber const& other) { return self >= other; })
      .def("DwordSize", &ipcl::BigNumber::DwordSize)
      .def("BitSize", &ipcl::BigNumber::BitSize)
      .def("data",
           [](ipcl::BigNumber const& self) {
             int bnBitLen;
             Ipp32u* bnData;
             ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
             int length = ipcl::BITSIZE_WORD(bnBitLen);
             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(bnData[i]);
             return py::make_tuple(length, l_dt);
           })
      .def_property_readonly_static(
          "Zero", [](const py::object&) { return ipcl::BigNumber::Zero(); })
      .def_property_readonly_static(
          "One", [](const py::object&) { return ipcl::BigNumber::One(); })
      .def_property_readonly_static(
          "Two", [](const py::object&) { return ipcl::BigNumber::Two(); })
      .def_property_readonly("tolist",
                             [](ipcl::BigNumber const& self) {
                               int bnBitLen;
                               Ipp32u* bnData;
                               ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
                               int length = ipcl::BITSIZE_WORD(bnBitLen);
                               py::list l_dt;
                               for (int i = 0; i < length; i++)
                                 l_dt.append(bnData[i]);
                               return l_dt;
                             })
      .def_property_readonly("val_alt",
                             [](ipcl::BigNumber const& self) {
                               std::string s_dec = baseconverter::BN2dec(self);
                               py::int_ dec = py::cast(s_dec);
                               return dec;
                             })
      .def_property_readonly("val",
                             [](ipcl::BigNumber const& self) {
                               int bnBitLen;
                               Ipp32u* bnData;
                               ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
                               int length = ipcl::BITSIZE_WORD(bnBitLen);
                               py::list l_dt;
                               for (int i = 0; i < length; i++)
                                 l_dt.append(bnData[i]);
                               return l_dt;
                             })
      .def_property_readonly("shape",
                             [](ipcl::BigNumber const& self) {
                               int bnBitLen;
                               ippsRef_BN(nullptr, &bnBitLen, nullptr, self);
                               int len = ipcl::BITSIZE_WORD(bnBitLen);
                               return len;
                             })
      .def(py::pickle(
          [](const ipcl::BigNumber& self) {  // __getstate__
            auto btl = py_ippUtils::BN2pylist(self);
            return py::make_tuple(btl.first, btl.second);
          },
          [](py::tuple t) {  // __setstate__
            size_t length = py::cast<size_t>(t[0]);
            py::list l_dt = t[1];
            Ipp32u* bnData = new Ipp32u[length];
            for (int i = 0; i < length; ++i)
              bnData[i] = py::cast<unsigned int>(l_dt[i]);
            return std::unique_ptr<ipcl::BigNumber>(
                new ipcl::BigNumber(bnData, length));
          }));
}
