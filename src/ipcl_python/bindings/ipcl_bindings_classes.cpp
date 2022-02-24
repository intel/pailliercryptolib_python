// Copyright (C) 2021-2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <memory>

#include "include/ipcl_bindings.h"

namespace py = pybind11;

void def_ipclPublicKey(py::module& m) {
  // Paillier publickey module
  py::class_<PaillierPublicKey>(m, "ipclPublicKey")
      .def(py::init([](py::int_ n) {  // deprecated
        std::string n_str = py::str(n);
        const BigNumber bn(n_str.c_str());
        PaillierPublicKey* ret = new PaillierPublicKey(bn, 1024);
        return ret;
      }))
      .def(py::init([](py::int_ n, bool enable_DJN) {  // deprecated
        std::string n_str = py::str(n);
        const BigNumber bn(n_str.c_str());
        PaillierPublicKey* ret = new PaillierPublicKey(bn, 1024);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def(py::init([](const BigNumber& n) {
        PaillierPublicKey* ret = new PaillierPublicKey(n, 1024);
        return ret;
      }))
      .def(py::init([](const BigNumber& n, bool enable_DJN) {
        PaillierPublicKey* ret = new PaillierPublicKey(n, 1024);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def(py::init([](py::int_ n, int bits) {  // deprecated
        std::string n_str = py::str(n);
        const BigNumber bn(n_str.c_str());
        PaillierPublicKey* ret = new PaillierPublicKey(bn, bits);
        return ret;
      }))
      .def(py::init([](py::int_ n, int bits, bool enable_DJN) {  // deprecated
        std::string n_str = py::str(n);
        const BigNumber bn(n_str.c_str());
        PaillierPublicKey* ret = new PaillierPublicKey(bn, bits);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def(py::init([](const BigNumber& n, int bits) {
        PaillierPublicKey* ret = new PaillierPublicKey(n, bits);
        return ret;
      }))
      .def(py::init([](const BigNumber& n, int bits, bool enable_DJN) {
        PaillierPublicKey* ret = new PaillierPublicKey(n, bits);
        if (enable_DJN) ret->enableDJN();
        return ret;
      }))
      .def("__repr__",
           [](const PaillierPublicKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPublicKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const PaillierPublicKey& self, const PaillierPublicKey& other) {
             return self.getN() == other.getN();
           })
      .def("__hash__",
           [](const PaillierPublicKey& self) {
             std::stringstream ss;
             ss << self.getN();
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("n", &PaillierPublicKey::getN)
      .def_property_readonly("length", &PaillierPublicKey::getBits)
      .def_property_readonly("nsquare", &PaillierPublicKey::getNSQ)
      .def("raw_encrypt",
           [](PaillierPublicKey& self, BigNumber& bn, bool make_secure) {
             BigNumber pt[8];
             pt[0] = bn;

             BigNumber ct[8];
             self.encrypt(ct, pt);
             return ct[0];
           })
      .def("raw_encrypt_buff8",  // 8 pack encryption with list input
           [](PaillierPublicKey& self, py::list value, bool make_secure) {
             size_t length = value.size();
             if (length > 8)
               throw std::out_of_range("Value size is larger than 8");
             BigNumber pData[8];
             for (int i = 0; i < length; i++)
               pData[i] = value[i].cast<BigNumber>();

             BigNumber ct[8];  // = std::make_unique<BigNumber>(8);
             self.encrypt(ct, pData, make_secure);
             py::list l_ct;
             for (int i = 0; i < length; i++) l_ct.append(ct[i]);
             return l_ct;
           })
      .def(
          "raw_encrypt_buff8",  // overloaded 8 pack encryption with numpy array
          [](PaillierPublicKey& self, py::array value, bool make_secure) {
            py::buffer_info buffer_info = value.request();
            size_t length = buffer_info.shape[0];
            if (length > 8)
              throw std::out_of_range("Value size is larger than 8");
            BigNumber* data = static_cast<BigNumber*>(buffer_info.ptr);

            BigNumber pData[8];
            for (int i = 0; i < length; i++) pData[i] = data[i];

            BigNumber ct[8];
            self.encrypt(ct, pData, make_secure);
            py::list l_ct;
            for (int i = 0; i < length; i++) l_ct.append(ct[i]);
            return l_ct;
          })
      .def("raw_encrypt_insecure",  // encrypt bn insecure, for plaintext
                                    // add/mul
           [](PaillierPublicKey& self, BigNumber& bn) {
             BigNumber ct;
             self.encrypt(ct, bn);
             return ct;
           })
      .def("encrypt",
           [](PaillierPublicKey& self, BigNumber& val, bool make_secure) {
             BigNumber pt[8];
             pt[0] = val;

             BigNumber ct[8];
             self.encrypt(ct, pt, make_secure);
             PaillierEncryptedNumber ret(&self, ct[0]);
             return ret;
           })
      .def("encrypt_buff8",  // encrypt 8 pack list to single
                             // PaillierEncryptedNumber
           [](PaillierPublicKey& self, py::list value, bool make_secure) {
             size_t length = value.size();
             if (length > 8)
               throw std::out_of_range("List size is larger than 8");
             BigNumber pData[8];
             for (int i = 0; i < length; i++) {
               pData[i] = value[i].cast<BigNumber>();
             }
             BigNumber ct[8];
             self.encrypt(ct, pData, make_secure);

             PaillierEncryptedNumber ret(&self, ct, length);
             return ret;
           })
      .def("encrypt_buff8",  // encrypt 8 pack array to single
                             // PaillierEncryptedNumber
           [](PaillierPublicKey& self, py::array value, bool make_secure) {
             py::buffer_info buffer_info = value.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("Array size is larger than 8");
             py::int_* data = static_cast<py::int_*>(buffer_info.ptr);

             BigNumber pData[8];
             for (int i = 0; i < 8; i++) {
               std::string s_val = py::str(data[i]);
               pData[i] = i < length ? BigNumber(s_val.c_str()) : 0;
             }
             BigNumber ct[8];
             self.encrypt(ct, pData, make_secure);

             PaillierEncryptedNumber ret(&self, ct, length);
             return ret;
           })
      .def(py::pickle(
          [](const PaillierPublicKey& self) {  // __getstate__
            BigNumber bn = self.getN();
            auto lbn = py_ippUtils::BN2pylist(bn);
            int bits = self.getBits();
            return py::make_tuple(lbn.second, bits);
          },
          [](py::tuple t) {  // __setstate__
            py::list l_bn = t[0];
            BigNumber n = py_ippUtils::pylist2BN(l_bn);
            int n_length = py::cast<int>(t[1]);
            PaillierPublicKey* pk = new PaillierPublicKey(n, n_length);
            return pk;
          }));
}

void def_ipclPrivateKey(py::module& m) {
  py::class_<PaillierPrivateKey>(m, "ipclPrivateKey")
      .def(py::init([](PaillierPublicKey* pubkey, const BigNumber& p,
                       const BigNumber& q) {
        return std::unique_ptr<PaillierPrivateKey>(
            new PaillierPrivateKey(pubkey, p, q));
      }))
      .def("__repr__",
           [](const PaillierPrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclPrivateKey " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__eq__",
           [](const PaillierPrivateKey& self, const PaillierPrivateKey& other) {
             return self.getQ() == other.getQ();
           })
      .def("__hash__",
           [](const PaillierPrivateKey& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return hashcode;
           })
      .def_property_readonly("public_key", &PaillierPrivateKey::getPubKey)
      .def_property_readonly("p", &PaillierPrivateKey::getP)
      .def_property_readonly("q", &PaillierPrivateKey::getQ)
      .def("decrypt",
           [](PaillierPrivateKey& self, const PaillierEncryptedNumber& value) {
             BigNumber tmp[8];
             tmp[0] = value.getBN();
             BigNumber dt[8];
             self.decrypt(dt, tmp);
             return dt[0];
           })
      .def("decrypt",  //  decrypt packed PaillierEncryptedNumber
           [](PaillierPrivateKey& self, const PaillierEncryptedNumber& value,
              int sz) {
             BigNumber this_bn[8];
             value.getArrayBN(this_bn);
             BigNumber pt[8];
             self.decrypt(pt, this_bn);
             py::list l_pt;
             for (int i = 0; i < sz; ++i) {
               l_pt.append(pt[i]);
             }
             return l_pt;
           })
      .def("decrypt_buff8",  // decrypt PaillierEncryptedNumber
           [](PaillierPrivateKey& self, const py::list& value) {
             size_t length = value.size();
             if (length > 8)
               throw std::out_of_range("Value size is larger than 8");
             BigNumber tmp[8];
             for (int i = 0; i < length; i++)
               tmp[i] = value[i].cast<PaillierEncryptedNumber>().getBN();
             BigNumber dt[8];
             self.decrypt(dt, tmp);

             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(dt[i]);
             return l_dt;
           })
      .def("decrypt_buff8",
           [](PaillierPrivateKey& self, const py::array& value) {
             py::buffer_info buffer_info = value.request();
             size_t length = buffer_info.shape[0];
             if (length > 8)
               throw std::out_of_range("Value size is larger than 8");
             PaillierEncryptedNumber* data =
                 static_cast<PaillierEncryptedNumber*>(buffer_info.ptr);
             BigNumber tmp[8];
             for (int i = 0; i < length; i++) tmp[i] = data[i].getBN();
             BigNumber dt[8];
             self.decrypt(dt, tmp);
             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(dt[i]);
             return l_dt;
           })
      .def("raw_decrypt",  // decrypt BigNumber
           [](PaillierPrivateKey& self, const BigNumber& value) {
             BigNumber tmp[8];
             tmp[0] = value;
             BigNumber dt[8];
             self.decrypt(dt, tmp);
             return dt[0];
           })
      .def("raw_decrypt_buff8",  // decrypt list of BigNumbers
           [](PaillierPrivateKey& self, const py::list& value) {
             size_t length = value.size();
             if (length > 8)
               throw std::out_of_range("Value size is larger than 8");
             BigNumber tmp[8];
             try {
               for (int i = 0; i < length; i++) {
                 tmp[i] = value[i].cast<BigNumber>();
               }
             } catch (int e) {
               throw std::invalid_argument("Value is not list of BigNumber");
             }

             BigNumber dt[8];
             self.decrypt(dt, tmp);
             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(dt[i]);
             return l_dt;
           })
      .def(
          "raw_decrypt_buff8",  // decrypt array of BigNumbers
          [](PaillierPrivateKey& self, const py::array& value) {
            py::buffer_info buffer_info = value.request();
            size_t length = buffer_info.shape[0];
            if (length > 8)
              throw std::out_of_range("Value size is larger than 8");
            BigNumber tmp[8];
            try {
              BigNumber* data = static_cast<BigNumber*>(buffer_info.ptr);
              for (int i = 0; i < length; i++) tmp[i] = data[i];
            } catch (int e) {
              throw std::invalid_argument("Value is not an array of BigNumber");
            }

            BigNumber dt[8];
            self.decrypt(dt, tmp);
            py::list l_dt;
            for (int i = 0; i < length; i++) l_dt.append(dt[i]);
            return l_dt;
          })
      .def(py::pickle(
          [](const PaillierPrivateKey& self) {  // __getstate__
            PaillierPublicKey* pub = self.getPubKey();
            BigNumber pubkeyN = pub->getN();
            auto _pubkeyN = py_ippUtils::BN2pylist(pubkeyN);
            int bits = pub->getBits();

            BigNumber p = self.getP();
            auto _p = py_ippUtils::BN2pylist(p);
            BigNumber q = self.getQ();
            auto _q = py_ippUtils::BN2pylist(q);

            return py::make_tuple(_pubkeyN.second, bits, _p.second, _q.second);
          },
          [](py::tuple t) {  // __setstate__
            py::list l_pubkeyN = t[0];
            BigNumber pubkeyN = py_ippUtils::pylist2BN(l_pubkeyN);
            int bits = py::cast<int>(t[1]);
            PaillierPublicKey* pub = new PaillierPublicKey(pubkeyN, bits);

            py::list l_p = t[2];
            BigNumber p = py_ippUtils::pylist2BN(l_p);
            py::list l_q = t[3];
            BigNumber q = py_ippUtils::pylist2BN(l_q);
            PaillierPrivateKey* pk = new PaillierPrivateKey(pub, p, q);
            return pk;
          }));
}

void def_ipclEncryptedNumber(py::module& m) {
  // PaillierEncryptedNumber
  py::class_<PaillierEncryptedNumber>(m, "ipclEncryptedNumber")
      .def(py::init<PaillierPublicKey*, const BigNumber>())
      .def(py::init<PaillierPublicKey*, const BigNumber*>())
      .def(py::init<PaillierPublicKey*, const uint32_t*>())
      .def(py::init([](PaillierPublicKey* pubkey, const py::list vals) {
        size_t length = vals.size();
        if (length > 8) throw std::out_of_range("List size is larger than 8");
        BigNumber pData[8];
        for (int i = 0; i < length; i++) {
          pData[i] = vals[i].cast<BigNumber>();
        }
        return PaillierEncryptedNumber(pubkey, pData);
      }))
      .def("__repr__",
           [](const PaillierEncryptedNumber& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclEncryptedNumber " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("__str__",
           [](const PaillierEncryptedNumber& self) {
             std::stringstream ss;
             ss << self.addr;
             std::size_t hashcode = std::hash<std::string>{}(ss.str());
             return std::string("<ipclEncryptedNumber " +
                                std::to_string(hashcode).substr(0, 10) + ">");
           })
      .def("public_key", &PaillierEncryptedNumber::getPK)
      .def("__add__",
           [](PaillierEncryptedNumber const& self,
              PaillierEncryptedNumber const& other) { return self + other; })
      .def("__mul__",
           [](PaillierEncryptedNumber const& self,
              PaillierEncryptedNumber const& other) { return self * other; })
      .def("__mul__",
           [](PaillierEncryptedNumber const& self, py::int_ other) {
             std::string s_obj = py::str(other);
             BigNumber tmp(s_obj.c_str());
             return self * tmp;
           })
      .def("__mul__", [](PaillierEncryptedNumber const& self,
                         BigNumber& other) { return self * other; })
      .def("rotate", &PaillierEncryptedNumber::rotate)
      .def("isSingle", &PaillierEncryptedNumber::isSingle)
      .def("__len__", &PaillierEncryptedNumber::getLength)
      .def("getBN", &PaillierEncryptedNumber::getBN)
      .def("getBN",
           [](PaillierEncryptedNumber const& self) { return self.getBN(); })
      .def("getAllBN",
           [](PaillierEncryptedNumber const& self) {
             BigNumber bn[8];
             self.getArrayBN(bn);
             py::list l_bn;
             if (self.isSingle()) {
               l_bn.append(bn[0]);
             } else {
               for (int i = 0; i < 8; ++i) l_bn.append(bn[i]);
             }
             return l_bn;
           })
      .def(py::pickle(
          [](const PaillierEncryptedNumber& self) {  // __getstate__
            PaillierPublicKey pub = self.getPK();
            auto lpubn = py_ippUtils::BN2pylist(pub.getN());

            int bits = pub.getBits();

            BigNumber bn[8];
            self.getArrayBN(bn);
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
            BigNumber pubn = py_ippUtils::pylist2BN(l_pubn);
            int bits = py::cast<int>(t[1]);
            PaillierPublicKey* pub = new PaillierPublicKey(pubn, bits);

            int length = py::cast<int>(t[2]);
            py::list l_bn = t[3];
            if (length == 1) {
              py::list lbn = l_bn[0];
              BigNumber bn = py_ippUtils::pylist2BN(lbn);
              return std::make_unique<PaillierEncryptedNumber>(pub, bn);
            }

            BigNumber bn[8];
            for (size_t i = 0; i < length; ++i) {
              py::list lbn = l_bn[i];
              bn[i] = py_ippUtils::pylist2BN(lbn);
            }
            return std::make_unique<PaillierEncryptedNumber>(pub, bn);
          }));
}

void def_BigNumber(py::module& m) {
  py::class_<BigNumber>(m, "ipclBigNumber")
      .def(py::init<BigNumber&>())
      .def(py::init(
          [](unsigned int obj) { return std::make_unique<BigNumber>(obj); }))
      .def(py::init([](py::list data) {
        size_t length = data.size();
        unsigned int* pData = new unsigned int[length];
        for (int i = 0; i < length; i++) {
          pData[i] = data[i].cast<unsigned int>();
        }
        return std::unique_ptr<BigNumber>(new BigNumber(pData, length));
      }))
      .def(py::init([](py::array_t<unsigned int> data) {
        py::buffer_info buffer_info = data.request();

        unsigned int* pData = static_cast<unsigned int*>(buffer_info.ptr);
        std::vector<ssize_t> shape = buffer_info.shape;
        return std::unique_ptr<BigNumber>(new BigNumber(pData, shape[0]));
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
           [](BigNumber const& self, unsigned int n) {
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
      .def("data",
           [](BigNumber const& self) {
             int bnBitLen;
             Ipp32u* bnData;
             ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
             int length = BITSIZE_WORD(bnBitLen);
             py::list l_dt;
             for (int i = 0; i < length; i++) l_dt.append(bnData[i]);
             return py::make_tuple(length, l_dt);
           })
      .def_property_readonly_static(
          "Zero", [](const py::object&) { return BigNumber::Zero(); })
      .def_property_readonly_static(
          "One", [](const py::object&) { return BigNumber::One(); })
      .def_property_readonly_static(
          "Two", [](const py::object&) { return BigNumber::Two(); })
      .def_property_readonly("tolist",
                             [](BigNumber const& self) {
                               int bnBitLen;
                               Ipp32u* bnData;
                               ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
                               int length = BITSIZE_WORD(bnBitLen);
                               py::list l_dt;
                               for (int i = 0; i < length; i++)
                                 l_dt.append(bnData[i]);
                               return l_dt;
                             })
      .def_property_readonly("val_alt",
                             [](BigNumber const& self) {
                               std::string s_dec = baseconverter::BN2dec(self);
                               py::int_ dec = py::cast(s_dec);
                               return dec;
                             })
      .def_property_readonly("val",
                             [](BigNumber const& self) {
                               int bnBitLen;
                               Ipp32u* bnData;
                               ippsRef_BN(nullptr, &bnBitLen, &bnData, self);
                               int length = BITSIZE_WORD(bnBitLen);
                               py::list l_dt;
                               for (int i = 0; i < length; i++)
                                 l_dt.append(bnData[i]);
                               return l_dt;
                             })
      .def_property_readonly("shape",
                             [](BigNumber const& self) {
                               int bnBitLen;
                               ippsRef_BN(nullptr, &bnBitLen, nullptr, self);
                               int len = BITSIZE_WORD(bnBitLen);
                               return len;
                             })
      .def(py::pickle(
          [](const BigNumber& self) {  // __getstate__
            auto btl = py_ippUtils::BN2pylist(self);
            return py::make_tuple(btl.first, btl.second);
          },
          [](py::tuple t) {  // __setstate__
            size_t length = py::cast<size_t>(t[0]);
            py::list l_dt = t[1];
            Ipp32u* bnData = new Ipp32u[length];
            for (int i = 0; i < length; ++i)
              bnData[i] = py::cast<unsigned int>(l_dt[i]);
            return std::unique_ptr<BigNumber>(new BigNumber(bnData, length));
          }));
}
