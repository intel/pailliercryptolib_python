# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from .bindings.fixedpoint import FixedPointNumber
from .bindings.ipcl_bindings import (
    ipclKeypair,
    ipclPublicKey,
    ipclPrivateKey,
    ipclPlainText,
    ipclCipherText,
    ipclBigNumber,
)
import numpy as np
import gmpy2
from typing import Union, Optional, Tuple


class PaillierKeypair(object):
    def __init__(self):
        pass

    @staticmethod
    def generate_keypair(
        n_length: int = 1024, enable_DJN: bool = True
    ) -> Tuple["PaillierPublicKey", "PaillierPrivateKey"]:
        """
        Invokes IPCL keypair generation

        Args:
            n_length: key length to generate public and private key pair.
                      Supports up to 2048 bits
            enable_DJN: Enables faster encrypt/decrypt scheme by
                        Damgård-Jurik-Nielsen (DJN)

        Returns:
            (PaillierPublicKey, PaillierPrivateKey): Tuple of public and
                                                     private key
        """
        keys = ipclKeypair.generate_keypair(n_length, enable_DJN)
        pub = PaillierPublicKey(keys[0])
        pri = PaillierPrivateKey(keys[1])
        return pub, pri


class PaillierPublicKey(object):
    def __init__(
        self,
        key: Union[ipclPublicKey, "PaillierPublicKey", int],
        n_length: Optional[int] = None,
        enable_DJN: Optional[bool] = None,
    ):
        """
        PaillierPublicKey constructor

        Args:
            key: ipcl_bindings.PaillierPublicKey or PaillierPublicKey
            n_length: (default=None) Needed when constructing w/ arbitrary key
        """
        if isinstance(key, ipclPublicKey):
            self.n = BNUtils.BN2int(key.n)
            self.pubkey = key
        elif isinstance(key, PaillierPublicKey):
            self = key
        elif (
            isinstance(key, int)
            and n_length is not None
            and enable_DJN is not None
        ):
            self.n = key
            self.pubkey = ipclPublicKey(
                BNUtils.int2BN(self.n), n_length, enable_DJN
            )
        else:
            raise ValueError(
                "PaillierPublicKey: PubKey should be either key value (n),"
                "PaillierPublicKey or IPP-PaillierPublicKey object"
            )
        self.max_int = self.n // 3 - 1
        self.nsquare = self.n * self.n

    def __getstate__(self):
        return (self.n, self.max_int, self.nsquare, self.pubkey)

    def __setstate__(self, state):
        self.n, self.max_int, self.nsquare, self.pubkey = state

    def __repr__(self):
        return self.pubkey.__repr__()

    def __str__(self):
        return self.pubkey.n

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return self.pubkey.__hash__()

    def apply_obfuscator(self):
        pass

    def encrypt(
        self,
        value: Union[np.ndarray, list, int, float],
        apply_obfuscator: bool = True,
    ):
        """
        Encrypts scalar or list/array of scalars

        Args:
            value: integer/float scalar of list/array of integers/floats
            apply_obfuscator: (default=True) Applies obfuscator to ciphertext.

        Returns:
            A single PaillierEncryptedNumber (scalar value) or numpy.ndarray
            of PaillierEncryptedNumber (list/array of integer/floats)
        """
        if np.isscalar(value):
            value = [value]

        enc, expo = [], []
        for val in value:
            if not (isinstance(val, (int, float, np.integer))):
                raise ValueError(
                    "encrypt: input value(s) should be integer or float"
                )
            encoding = FixedPointNumber.encode(val, self.n, self.max_int)
            enc.append(BNUtils.int2BN(encoding.encoding))
            expo.append(encoding.exponent)
        plaintext = ipclPlainText(enc)
        ct = self.pubkey.encrypt(plaintext, apply_obfuscator)

        return PaillierEncryptedNumber(
            self, ct, exponents=expo, length=len(value)
        )


class PaillierPrivateKey(object):
    def __init__(
        self,
        key: Union[ipclPrivateKey, ipclPublicKey, PaillierPublicKey],
        p: Optional[int] = None,
        q: Optional[int] = None,
    ):
        """
        PaillierPrivateKey constructor

        Args:
            key: ipcl_bindings.PaillierPrivateKey or
                 ipcl_bindings.PaillierPublicKey with p and q (private keys)
        """
        if isinstance(key, ipclPrivateKey):
            self.prikey = key
            self.public_key = PaillierPublicKey(key.public_key)
        elif isinstance(key, ipclPublicKey) and p is not None and q is not None:
            self.prikey = ipclPrivateKey(
                key, BNUtils.int2BN(p), BNUtils.int2BN(q)
            )
            self.public_key = PaillierPublicKey(key)
        elif (
            isinstance(key, PaillierPublicKey)
            and p is not None
            and q is not None
        ):
            self.prikey = ipclPrivateKey(
                key.pubkey, BNUtils.int2BN(p), BNUtils.int2BN(q)
            )
            self.public_key = key
        else:
            raise KeyError(
                "key should be either Private key or Public key (with p and q)"
            )

    def __getstate__(self):
        return self.prikey

    def __setstate__(self, state):
        self.prikey = state
        self.public_key = PaillierPublicKey(self.prikey.public_key)

    def __eq__(self, other: "PaillierPrivateKey"):
        return (self.prikey.p == other.prikey.p) and (
            self.prikey.q == other.prikey.q
        )

    def __hash__(self):
        return self.prikey.__hash__()

    def __repr__(self):
        return self.prikey.__repr__()

    def decrypt(
        self,
        encrypted_number: "PaillierEncryptedNumber",
    ):
        """
        Decrypts PaillierEncryptedNumber

        Args:
            encrypted_number: PaillierEncryptedNumber

        Returns:
            array or single integer of decrypted encrypted number
        """
        if encrypted_number.public_key != self.public_key:
            raise ValueError("decrypt: Public key mismatch")

        decrypted = self.prikey.decrypt(encrypted_number.ciphertext())
        l_pt, l_expo = decrypted.getTexts(), encrypted_number.exponent()

        ret = []
        for pt, expo in zip(l_pt, l_expo):
            dec = FixedPointNumber(
                BNUtils.BN2int(pt),
                expo,
                self.public_key.n,
                self.public_key.max_int,
            )
            ret.append(dec.decode())

        return ret if len(encrypted_number) > 1 else ret[0]


class PaillierEncryptedNumber(object):
    def __init__(
        self,
        public_key: PaillierPublicKey,
        ciphertext: ipclCipherText,
        exponents: list,
        length: int,
    ):
        """
        PaillierEncryptedNumber constructor

        Args:
            public_key: PaillierPublicKey
            ciphertext: ipcl_bindings.PaillierEncryptedNumber
            exponent: exponent of ciphertext
        """

        # check public key match
        if ciphertext.public_key == public_key.pubkey:
            pass
        else:
            raise ValueError("PaillierEncryptedNumber: public key mismatch")
        self.__exponents = exponents
        self.public_key = public_key
        self.__ipclCipherText = ciphertext
        self.__length = length

    def __repr__(self):
        return self.__ipclCipherText.__repr__()

    def __getstate__(self) -> tuple:
        return (
            self.public_key,
            self.__length,
            self.exponent(),
            self.ciphertextBN(),
        )

    def __setstate__(self, state: tuple):
        self.public_key, self.__length, self.__exponents, ciphertextBN = state
        self.__ipclCipherText = ipclCipherText(
            self.public_key.pubkey, ciphertextBN
        )

    def __len__(self) -> int:
        return self.__length

    def ciphertext(self) -> ipclCipherText:
        return self.__ipclCipherText

    def ciphertextBN(self, idx: Optional[int] = None):
        """
        Getter function for obfuscated ciphertext
        Args:
            idx: index in the ciphertext array. If None, returns
                 list of entire ciphertexts
        Returns:
            if idx is None, returns entire ciphertexts in lists, otherwise
            returns ciphertext of index
        """
        if idx is None:
            return self.__ipclCipherText.getTexts()

        if idx < 0 or idx >= self.__length:
            raise IndexError("ciphertext: idx out of range")

        return self.__ipclCipherText[idx]

    def exponent(self, idx: Optional[int] = None):
        """
        Getter function for exponents
        Args:
            idx: index in the list of exponents. If None, returns
                 entire exponents list
        Returns:
            if idx is None, returns entire exponents list, otherwise
            returns exponent in index
        """
        if idx is None:
            return self.__exponents

        if idx < 0 or idx >= self.__length:
            raise IndexError("exponent: idx out of range")

        return self.__exponents[idx]

    def __add__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if (
            self.__length == 1
            and isinstance(other, PaillierEncryptedNumber)
            and len(other) > 1
        ):
            return other.__raw_add(self)
        return self.__raw_add(other)

    def __radd__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if (
            self.__length == 1
            and isinstance(other, PaillierEncryptedNumber)
            and len(other) > 1
        ):
            return other.__raw_add(self)
        return self.__raw_add(other)

    def __sub__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if isinstance(other, list):
            other = np.array(other)
        return self.__raw_add(other * -1.0)

    def __rsub__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        return self.__sub__(other)

    def __rmul__(
        self, other: Union[np.ndarray, list, int, float]
    ) -> "PaillierEncryptedNumber":
        return self.__mul__(other)

    def __truediv__(
        self, other: Union[np.ndarray, list, int, float]
    ) -> "PaillierEncryptedNumber":
        if isinstance(other, list):
            other = np.array(other)
        return self.__mul__(1.0 / other)

    def __mul__(
        self, other: Union[np.ndarray, list, float, int]
    ) -> "PaillierEncryptedNumber":
        if np.isscalar(other):  # if scalar - do broadcast
            encode = FixedPointNumber.encode(
                other, self.public_key.n, self.public_key.max_int
            )
            pt = encode.encoding
            pt_exponent = encode.exponent
            if pt < 0 or pt >= self.public_key.n:
                raise ValueError(
                    "PaillierEncryptedNumber.__mul__:"
                    " Scalar out of bounds: %i" % pt
                )
            if pt >= self.public_key.n - self.public_key.max_int:
                # invert all ciphertext
                neg_ct = []
                res_expo = []
                for _ct, _expo in zip(self.ciphertextBN(), self.exponent()):
                    neg_ct.append(
                        BNUtils.int2BN(
                            gmpy2.invert(
                                BNUtils.BN2int(_ct), self.public_key.nsquare
                            )
                        )
                    )
                    res_expo.append(_expo + pt_exponent)

                neg_ct_ipclCipherText = ipclCipherText(
                    self.public_key.pubkey, neg_ct
                )
                neg_pt = BNUtils.int2BN(self.public_key.n - pt)
                neg_pt_ipclPlainText = ipclPlainText(neg_pt)

                res_ct = neg_ct_ipclCipherText * neg_pt_ipclPlainText

                return PaillierEncryptedNumber(
                    self.public_key, res_ct, res_expo, self.__length
                )

            else:
                res_expo = [_expo + pt_exponent for _expo in self.exponent()]
                pt_ipclPlainText = ipclPlainText(BNUtils.int2BN(pt))
                res_ct = self.ciphertext() * pt_ipclPlainText
                return PaillierEncryptedNumber(
                    self.public_key, res_ct, res_expo, self.__length
                )

        else:  # non scalar
            if len(other) != self.__length:
                raise ValueError(
                    "PaillierEncryptedNumber.__mul__:" " Multiply size mismatch"
                )
            this_pt = []
            res_expo = []
            this_ct = []
            l_bn = self.ciphertextBN()

            for _ct, _ct_expo, _pt in zip(l_bn, self.exponent(), other):
                encode = FixedPointNumber.encode(
                    _pt, self.public_key.n, self.public_key.max_int
                )
                pt = encode.encoding
                pt_exponent = encode.exponent

                res_expo.append(_ct_expo + pt_exponent)
                if pt < 0 or pt >= self.public_key.n:
                    raise ValueError("Scalar out of bounds: %i" % pt)

                if pt >= self.public_key.n - self.public_key.max_int:
                    # invert corresponding ciphertext
                    this_pt.append(BNUtils.int2BN(self.public_key.n - pt))
                    this_ct.append(
                        BNUtils.int2BN(
                            gmpy2.invert(
                                BNUtils.BN2int(_ct), self.public_key.nsquare
                            )
                        )
                    )
                else:
                    this_pt.append(BNUtils.int2BN(pt))
                    this_ct.append(_ct)

            ct_ipclCipherText = ipclCipherText(self.public_key.pubkey, this_ct)
            pt_ipclPlainText = ipclPlainText(this_pt)

            res_ct = ct_ipclCipherText * pt_ipclPlainText

            return PaillierEncryptedNumber(
                self.public_key, res_ct, res_expo, self.__length
            )

    def __raw_add(
        self,
        other: Union["PaillierEncryptedNumber", int, float, np.ndarray, list],
    ) -> "PaillierEncryptedNumber":

        # PlainText array or list
        if isinstance(other, np.ndarray) or isinstance(other, list):
            if self.__length != len(other):
                raise ValueError(
                    "PaillierEncryptedNumber.__raw_add: array(list) size"
                    " mismatch with PaillierEncryptedNumber"
                )
            other = self.public_key.encrypt(other, apply_obfuscator=False)
        # PlainText scalar - broadcasting
        elif np.isscalar(other) and (
            isinstance(other, int) or isinstance(other, float)
        ):
            other = self.public_key.encrypt(other, apply_obfuscator=False)
        elif isinstance(other, PaillierEncryptedNumber):
            if self.public_key != other.public_key:
                raise ValueError("__raw_add: PublicKey mismatch")
            if self.__length != len(other) and len(other) > 1:
                raise ValueError(
                    "__raw_add: CipherText size mismatch"
                    " with PaillierEncryptedNumber"
                )

        # align self vs other (scalar)
        self_ct_aligned, other_aligned, res_expo = self.__align_exponent(
            self.ciphertext(),
            self.exponent(),
            other.ciphertext(),
            other.exponent(),
        )
        res_ct = self_ct_aligned + other_aligned
        return PaillierEncryptedNumber(
            self.public_key, res_ct, res_expo, self.__length
        )

    def increase_exponent_to(
        self, x: ipclCipherText, x_expo: Union[np.ndarray, list], exponent: int
    ) -> ipclCipherText:
        """
        Increases exponent of py_ipp_paillier.PaillierEncryptedNumber
        to target exponent
        Args:
            x: ipclCipherText
            x_expo: list of exponents of x
            exponent: target exponent. Needs to be larger than current exponent
        Returns:
            Updated encrypted number with increased exponent
        """

        x_factor = []
        x_pass = True

        for x_exponent in x_expo:
            if x_exponent >= exponent:
                x_factor.append(BNUtils.int2BN(1))
            else:
                x_factor.append(
                    BNUtils.int2BN(
                        pow(FixedPointNumber.BASE, exponent - x_exponent)
                    )
                )
                x_pass = False

        if not x_pass:
            x_factor_ipclPlainText = ipclPlainText(x_factor)
            x_ipclCipherText_factored = x * x_factor_ipclPlainText
            return x_ipclCipherText_factored

        # No need to factor exponents
        return x

    def __align_exponent(
        self,
        x_ct: ipclCipherText,
        x_expo: Union[list, np.ndarray],
        y_ct: ipclCipherText,
        y_expo: Union[list, np.ndarray],
    ) -> Tuple[ipclCipherText, ipclCipherText, list]:
        """
        Aligns exponent of self and other ipclCipherText
        Args:
            ct: target ipclCipherText
            expo: list of exponents of the target ciphertext
        Returns:
            tuple of two exponent matching ipclCipherTexts (self, target) and
            list of matched exponents
        """

        x_factor = []
        x_factor_exponent = []

        y_factor = []
        y_factor_exponent = []

        ret_exponent = []

        x_pass = True
        y_pass = True

        # if broadcasting
        if len(y_ct) == 1:
            for _x_expo in x_expo:
                if _x_expo > y_expo[0]:
                    y_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, _x_expo - y_expo[0])
                        )
                    )
                    y_factor_exponent.append(_x_expo - y_expo[0])
                    x_factor.append(ipclBigNumber.One)
                    x_factor_exponent.append(0)
                    y_pass = False
                    ret_exponent.append(_x_expo)
                elif _x_expo < y_expo[0]:
                    x_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, y_expo[0] - _x_expo)
                        )
                    )
                    x_factor_exponent.append(y_expo[0] - _x_expo)
                    y_factor.append(ipclBigNumber.One)
                    y_factor_exponent.append(0)
                    x_pass = False
                    ret_exponent.append(y_expo[0])
                else:
                    x_factor.append(ipclBigNumber.One)
                    x_factor_exponent.append(0)
                    y_factor.append(ipclBigNumber.One)
                    y_factor_exponent.append(0)
                    ret_exponent.append(y_expo[0])

            x_factored_CipherText, y_factored_CipherText = None, None
            if not x_pass:
                x_factor_PlainText = ipclPlainText(x_factor)
                x_factored_CipherText = x_ct * x_factor_PlainText
            else:
                x_factored_CipherText = x_ct

            if not y_pass:
                y_factor_PlainText = ipclPlainText(y_factor)
                y_factored_CipherText = (
                    ipclCipherText(
                        self.public_key.pubkey, y_ct.getTexts() * len(x_ct)
                    )
                    * y_factor_PlainText
                )
            else:
                y_factored_CipherText = y_ct

            return x_factored_CipherText, y_factored_CipherText, ret_exponent

        else:
            for _x_expo, _y_expo in zip(x_expo, y_expo):
                if _x_expo > _y_expo:
                    y_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, _x_expo - _y_expo)
                        )
                    )
                    y_factor_exponent.append(_x_expo - _y_expo)
                    x_factor.append(ipclBigNumber.One)
                    x_factor_exponent.append(0)
                    y_pass = False
                    ret_exponent.append(_x_expo)
                elif _x_expo < _y_expo:
                    x_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, _y_expo - _x_expo)
                        )
                    )
                    x_factor_exponent.append(_y_expo - _x_expo)
                    y_factor.append(ipclBigNumber.One)
                    y_factor_exponent.append(0)
                    x_pass = False
                    ret_exponent.append(_y_expo)
                else:
                    x_factor.append(ipclBigNumber.One)
                    x_factor_exponent.append(0)
                    y_factor.append(ipclBigNumber.One)
                    y_factor_exponent.append(0)
                    ret_exponent.append(_y_expo)

            x_factored_CipherText, y_factored_CipherText = None, None
            if not x_pass:
                x_factor_PlainText = ipclPlainText(x_factor)
                x_factored_CipherText = x_ct * x_factor_PlainText
            else:
                x_factored_CipherText = x_ct

            if not y_pass:
                y_factor_PlainText = ipclPlainText(y_factor)
                y_factored_CipherText = y_ct * y_factor_PlainText
            else:
                y_factored_CipherText = y_ct

            return x_factored_CipherText, y_factored_CipherText, ret_exponent

    def length(self) -> int:
        return self.__length

    def sum(self) -> "PaillierEncryptedNumber":
        max_exponent = max(self.exponent())
        ct_aligned_ipclCipherText = self.increase_exponent_to(
            self.__ipclCipherText, self.exponent(), max_exponent
        )

        max_step = 2 ** ((self.__len__() - 1).bit_length())
        padded_ct = None
        if max_step > self.__len__():
            zero_ct = self.public_key.encrypt(0, apply_obfuscator=False)
            padded_list = (
                ct_aligned_ipclCipherText.getTexts()
                + zero_ct.ciphertextBN() * (max_step - self.__len__())
            )
            padded_ct = ipclCipherText(self.public_key.pubkey, padded_list)
        else:
            padded_ct = ct_aligned_ipclCipherText

        step = 1
        while step < max_step:
            tmp = padded_ct.rotate(step)
            padded_ct = padded_ct + tmp
            step = step << 1

        res_ipclCipherText = ipclCipherText(
            self.public_key.pubkey, padded_ct[0]
        )
        return PaillierEncryptedNumber(
            self.public_key,
            res_ipclCipherText,
            exponents=[max_exponent],
            length=1,
        )

    def mean(self) -> "PaillierEncryptedNumber":
        _sum = self.sum()
        return _sum / self.__len__()

    def dot(self, other: Union[np.ndarray, list]) -> "PaillierEncryptedNumber":
        if len(other) != self.__len__():
            raise ValueError("dot: input size mismatch with ciphertext")

        elemul = self.__mul__(other)
        return elemul.sum()


class BNUtils:
    # slice first then send array
    @staticmethod
    def int2BN(val: int) -> ipclBigNumber:
        """
        Convert Python integer to BigNumber

        Args:
            val: integer

        Returns:
            BigNumber representation of val
        """
        if val == 0:
            return ipclBigNumber.Zero
        elif val == 1:
            return ipclBigNumber.One
        elif val == 2:
            return ipclBigNumber.Two

        ret = []
        while val > 0:
            ret.append(val & (0xFFFFFFFF))
            val = val >> 32
        ret_bn = ipclBigNumber(ret)

        return ret_bn

    @staticmethod
    def BN2int(val: ipclBigNumber) -> int:
        """
        Convert BigNumber to Python integer

        Args:
            val: BigNumber

        Returns:
            Python integer representation of BigNumber
        """
        ret = 0
        sz, arr = val.data()
        for i in reversed(range(sz)):
            ret += arr[i] << (32 * i)
        return ret
