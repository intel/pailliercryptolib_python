# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from .bindings.fixedpoint import FixedPointNumber
from .bindings.ipcl_bindings import (
    ipclKeypair,
    ipclPublicKey,
    ipclPrivateKey,
    ipclEncryptedNumber,
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
                "PubKey should be either key value (n),"
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
        target_exponent: int = 15,
    ):
        """
        Encrypts scalar or list/array of scalars

        Args:
            value: integer/float scalar of list/array of integers/floats
            apply_obfuscator: (default=True) Applies obfuscator to ciphertext.
            target_exponent: (default=14) aligns exponents of inputs

        Returns:
            A single PaillierEncryptedNumber (scalar value) or numpy.ndarray
            of PaillierEncryptedNumber (list/array of integer/floats)
        """
        if isinstance(value, str) or isinstance(value, complex):
            raise ValueError("input value(s) should be integer or float")

        if np.isscalar(value):
            value = [value]

        length = len(value)
        encryptednumber = []
        all_exponents = []

        def chunker(seq, sz):
            for pos in range(0, len(seq), sz):
                yield seq[pos : pos + sz]

        for chunk in chunker(value, 8):
            encodings = []
            exponents = []
            for v in chunk:
                enc = FixedPointNumber.encode(v, self.n, self.max_int)
                encodings.append(BNUtils.int2BN(enc.encoding))
                exponents.append(enc.exponent)

            all_exponents.append(exponents)
            encryptednumber.append(
                self.pubkey.encrypt_buff8(encodings, apply_obfuscator)
            )

        return PaillierEncryptedNumber(
            self,
            encryptednumber,
            exponents=all_exponents,
            length=length,
            target_exponent=target_exponent,
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
        self.public_key = PaillierPublicKey(state.public_key)

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
        Decrypts single or list/array of PaillierEncryptedNumber

        Args:
            encrypted_number: PaillierEncryptedNumber

        Returns:
            array or single BigNumber of decrypted encrypted_number
        """
        if not isinstance(encrypted_number.ciphertext(), list):
            raise ValueError(
                "Incorrect PaillierEncryptedNumber.ciphertext() type"
            )

        if encrypted_number.public_key != self.public_key:
            raise ValueError("Key mismatch")

        ret = []
        l_ct, l_expo = encrypted_number.ciphertext(), encrypted_number.exponents
        for ct, expo in zip(l_ct, l_expo):
            pt = self.prikey.decrypt(ct, 8)
            l_val = []
            for _pt, _expo in zip(pt, expo):
                dec = FixedPointNumber(
                    BNUtils.BN2int(_pt),
                    _expo,
                    self.public_key.n,
                    self.public_key.max_int,
                )
                l_val.append(dec.decode())
            ret = ret + l_val

        return (
            ret[: encrypted_number.length]
            if encrypted_number.length > 1
            else ret[0]
        )


class PaillierEncryptedNumber(object):
    def __init__(
        self,
        public_key: PaillierPublicKey,
        ciphertext: list,
        exponents: list,
        length: int,
        target_exponent: Optional[int] = None,
    ):
        """
        PaillierEncryptedNumber constructor

        Args:
            public_key: PaillierPublicKey
            ciphertext: list of ipclEncryptedNumber
            exponents: list of exponents of stored ciphertexts
            length: length of PaillierEncryptedNumber ciphertexts
            target_exponent: aligned exponent value
        """
        if not all(isinstance(i, ipclEncryptedNumber) for i in ciphertext):
            raise ValueError(
                "Incompatible type: must be list or single ipclEncryptedNumber"
            )

        self.exponents = exponents
        self.public_key = public_key
        self.ippEncryptedNumber = ciphertext
        self._max_exponent = target_exponent
        self.length = length

    def __repr__(self):
        reprstr = "[ "
        for ien in self.ippEncryptedNumber:
            reprstr = reprstr + ien.__repr__()
        reprstr = reprstr + " ]"

        return reprstr

    def __getstate__(self) -> tuple:
        return (
            self.length,
            self.exponents,
            self._max_exponent,
            self.ippEncryptedNumber,
        )

    def __setstate__(self, state):
        (
            self.length,
            self.exponents,
            self._max_exponent,
            self.ippEncryptedNumber,
        ) = state
        self.public_key = PaillierPublicKey(
            self.ippEncryptedNumber[0].public_key()
        )

    def ciphertext(self, idx: Optional[int] = None):
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
            return self.ippEncryptedNumber
        else:
            if idx >= self.length:
                raise IndexError("Idx is larger than size", self.length)
            return self.ippEncryptedNumber[int(idx / 8)].getBN(idx & 7)

    def __len__(self) -> int:
        return self.length

    def __add__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if (
            self.length == 1
            and isinstance(other, PaillierEncryptedNumber)
            and other.length > 1
        ):
            return other.__raw_add(self)
        return self.__raw_add(other)

    def __radd__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if (
            self.length == 1
            and isinstance(other, PaillierEncryptedNumber)
            and other.length > 1
        ):
            return other.__raw_add(self)
        return self.__add__(other)

    def __sub__(
        self,
        other: Union["PaillierEncryptedNumber", np.ndarray, list, int, float],
    ) -> "PaillierEncryptedNumber":
        if isinstance(other, list):
            other = np.array(other)
        return self.__raw_add(other * -1)

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
        return self.__mul__(1 / other)

    def __mul__(
        self, scalar: Union[np.ndarray, list, float, int]
    ) -> "PaillierEncryptedNumber":
        ret = []
        ret_exponents = []
        if np.isscalar(scalar):
            encode = FixedPointNumber.encode(
                scalar,
                self.public_key.n,
                self.public_key.max_int,
            )
            pt = encode.encoding
            pt_exponent = encode.exponent

            if pt < 0 or pt >= self.public_key.n:
                raise ValueError("Scalar out of bounds: %i" % pt)

            if pt >= self.public_key.n - self.public_key.max_int:
                neg_scalar = BNUtils.int2BN(self.public_key.n - pt)
                neg_scalar_ippEncryptedNumber = ipclEncryptedNumber(
                    self.public_key.pubkey, [neg_scalar] * 8
                )

                for _pen, l_exponents in zip(
                    self.ippEncryptedNumber, self.exponents
                ):
                    l_bn = _pen.getAllBN()
                    neg_ct = [
                        BNUtils.int2BN(
                            gmpy2.invert(
                                BNUtils.BN2int(bn), self.public_key.nsquare
                            )
                        )
                        for bn in l_bn
                    ]
                    neg_ippEncryptedNumber = ipclEncryptedNumber(
                        self.public_key.pubkey, neg_ct
                    )

                    ret.append(
                        neg_ippEncryptedNumber * neg_scalar_ippEncryptedNumber
                    )
                    ret_exponents.append(
                        [pt_exponent + expo for expo in l_exponents]
                    )

            else:
                pt_bn = BNUtils.int2BN(pt)
                scalar_ippEncryptedNumber = ipclEncryptedNumber(
                    self.public_key.pubkey, [pt_bn] * 8
                )
                for _pen, l_exponents in zip(
                    self.ippEncryptedNumber, self.exponents
                ):
                    ret.append(_pen * scalar_ippEncryptedNumber)
                    ret_exponents.append(
                        [pt_exponent + expo for expo in l_exponents]
                    )

        else:
            if len(scalar) != self.length:
                raise ValueError(
                    "Multiply size mismatch: multiplier should be"
                    "either single scalar or np.ndarray or list"
                    "of same size with %i" % self.length
                )
            for i, (_pen, this_ct_exponent) in enumerate(
                zip(self.ippEncryptedNumber, self.exponents)
            ):
                this_pt = []
                this_pt_exponent = []
                this_ct = []

                l_bn = _pen.getAllBN()

                for _ct, _pt in zip(l_bn, scalar[i * 8 : i * 8 + 8]):
                    encode = FixedPointNumber.encode(
                        _pt,
                        self.public_key.n,
                        self.public_key.max_int,
                    )
                    pt = encode.encoding
                    pt_exponent = encode.exponent
                    if pt < 0 or pt >= self.public_key.n:
                        raise ValueError("Scalar out of bounds: %i" % pt)

                    if pt >= self.public_key.n - self.public_key.max_int:
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
                    this_pt_exponent.append(pt_exponent)

                this_ct_ippEncryptedNumber = ipclEncryptedNumber(
                    self.public_key.pubkey, this_ct
                )
                this_pt_ippEncryptedNumber = ipclEncryptedNumber(
                    self.public_key.pubkey, this_pt
                )

                ret.append(
                    this_ct_ippEncryptedNumber * this_pt_ippEncryptedNumber
                )
                ret_exponents.append(
                    [
                        this_expo + pt_expo
                        for this_expo, pt_expo in zip(
                            this_ct_exponent, this_pt_exponent
                        )
                    ]
                )

        return PaillierEncryptedNumber(
            self.public_key,
            ret,
            length=self.length,
            exponents=ret_exponents,
        )

    def dot(self, other: Union[np.ndarray, list]) -> "PaillierEncryptedNumber":
        """
        Dot operator
        Args:
            other: array/list of plaintexts, must be same size of self
        Returns:
            Dot product of self and other (list of plaintexts with same size)
        """
        if np.isscalar(other):
            raise ValueError("Dot product cannot take scalar input")
        if isinstance(other, list) or isinstance(other, np.ndarray):
            if len(other) != self.length:
                raise ValueError(
                    "Dot product requires input to be a list or"
                    " np.ndarray with same size"
                )

        elemul = self.__mul__(other)
        return elemul.sum()

    def sum(self) -> "PaillierEncryptedNumber":
        """
        Sum operator
        Returns:
            Sum of all ciphertexts
        """
        ret = self.ippEncryptedNumber[0]
        ret_exponent = self.exponents[0]

        for _pen, _expo in zip(self.ippEncryptedNumber[1:], self.exponents[1:]):
            ret, _pen, aligned_exponent = self.__align_exponent(
                ret, ret_exponent, _pen, _expo
            )
            ret = ret + _pen
            ret_exponent = aligned_exponent

        # increase all exponent to max value to reduce overhead
        max_exponent = max(ret_exponent)
        ret = self.increase_exponent_to(ret, ret_exponent, max_exponent)
        ret_exponent = [max_exponent] * 8

        # shift method
        # shift 4
        tmp = ret.rotate(4)
        ret = ret + tmp

        # shift 2
        tmp = ret.rotate(2)
        ret = ret + tmp

        # shift 1
        tmp = ret.rotate(1)
        ret = ret + tmp

        ret_ippEncryptedNumber = ipclEncryptedNumber(
            self.public_key.pubkey, [ret.getBN()]
        )

        return PaillierEncryptedNumber(
            self.public_key,
            [ret_ippEncryptedNumber],
            exponents=[[max_exponent]],
            length=1,
            target_exponent=self._max_exponent,
        )

    def mean(self) -> "PaillierEncryptedNumber":
        """
        Mean operator
        Returns:
            Mean of all ciphertexts
        """
        sum = self.sum()
        return sum / float(self.length)

    def __raw_add(
        self,
        other: Union[np.ndarray, list, int, float, "PaillierEncryptedNumber"],
    ) -> "PaillierEncryptedNumber":
        ret = []
        ret_exponent = []

        # plaintext array
        if isinstance(other, np.ndarray) or isinstance(other, list):
            if self.length != len(other):
                raise ValueError(
                    "Add size mismatch: Other should be either"
                    "PaillierEncryptedNumber Ciphertext with the same size or"
                    "Plaintext scalar(int, float) or np.ndarray/list of "
                    "same size with %i" % self.length
                )

            other = self.public_key.encrypt(
                other,
                apply_obfuscator=False,
            )
        # plaintext single scalar - broadcasting
        elif isinstance(other, int) or isinstance(other, float):
            other = self.public_key.encrypt(
                [other] * 8,
                apply_obfuscator=False,
            )
        elif isinstance(other, PaillierEncryptedNumber):
            if self.public_key != other.public_key:
                raise KeyError("Public key mismatch")
            if len(other) == 1:
                other_bn = [other.ippEncryptedNumber[0].getBN()] * 8
                other_exponent = [other.exponents[0][0]] * 8
                other_ippEncryptedNumber = ipclEncryptedNumber(
                    self.public_key.pubkey, other_bn
                )
                other = PaillierEncryptedNumber(
                    self.public_key,
                    [other_ippEncryptedNumber],
                    [other_exponent],
                    length=8,
                )
            elif self.length != len(other) and len(other) > 1:
                raise ValueError(
                    "Add size mismatch: Other should be either"
                    "Ciphertext scalar, PaillierEncryptedNumber of same size"
                    "or Plaintext scalar(int, float) or np.ndarray/list of "
                    "same size with %i" % self.length
                )
        else:
            raise TypeError(
                "Invalid input - int/float scalar (or array) or"
                "PaillierEncryptedNumber type allowed"
            )

        # align exponent of two ciphertexts
        if len(other.ippEncryptedNumber) == 1:
            for _self_pen, _self_expo in zip(
                self.ippEncryptedNumber, self.exponents
            ):
                (
                    self_ippEncryptedNumber_factored,
                    other_ippEncryptedNumber_factored,
                    aligned_exponents,
                ) = self.__align_exponent(
                    _self_pen,
                    _self_expo,
                    other.ippEncryptedNumber[0],
                    other.exponents[0],
                )

                ret.append(
                    self_ippEncryptedNumber_factored
                    + other_ippEncryptedNumber_factored
                )
                ret_exponent.append(aligned_exponents)

        else:
            for _self_pen, _self_expo, _other_pen, _other_expo in zip(
                self.ippEncryptedNumber,
                self.exponents,
                other.ippEncryptedNumber,
                other.exponents,
            ):

                (
                    self_ippEncryptedNumber_factored,
                    other_ippEncryptedNumber_factored,
                    aligned_exponents,
                ) = self.__align_exponent(
                    _self_pen, _self_expo, _other_pen, _other_expo
                )
                ret.append(
                    self_ippEncryptedNumber_factored
                    + other_ippEncryptedNumber_factored
                )
                ret_exponent.append(aligned_exponents)

        return PaillierEncryptedNumber(
            self.public_key,
            ret,
            length=self.length,
            exponents=ret_exponent,
        )

    def __align_exponent(
        self,
        x: ipclEncryptedNumber,
        x_expo: Union[np.ndarray, list],
        y: ipclEncryptedNumber,
        y_expo: Union[np.ndarray, list],
    ) -> Tuple[ipclEncryptedNumber, ipclEncryptedNumber, list]:
        """
        Aligns exponent of two py_ipp_paillier.PaillierEncryptedNumbers
        Args:
            x, y: py_ipp_paillier.PaillierEncryptedNumbers
            x_expo, y_expo: list of exponents for respective encrypted numbers
        Returns:
            tuple of two exponent matching PaillierEncryptedNumbers and
            list of matched exponents
        """

        self_exponent = x_expo
        other_exponent = y_expo

        self_factor = []
        self_factor_exponent = []
        other_factor = []
        other_factor_exponent = []
        ret_exponent = []

        self_pass = True
        other_pass = True

        for x_exponent, y_exponent in zip(self_exponent, other_exponent):
            if x_exponent > y_exponent:
                other_factor.append(
                    BNUtils.int2BN(
                        pow(
                            FixedPointNumber.BASE,
                            x_exponent - y_exponent,
                        )
                    )
                )
                other_factor_exponent.append(x_exponent - y_exponent)
                self_factor.append(BNUtils.int2BN(1))
                self_factor_exponent.append(0)
                other_pass = False
                ret_exponent.append(x_exponent)
            elif x_exponent < y_exponent:
                self_factor.append(
                    BNUtils.int2BN(
                        pow(
                            FixedPointNumber.BASE,
                            y_exponent - x_exponent,
                        )
                    )
                )
                self_factor_exponent.append(y_exponent - x_exponent)
                other_factor.append(BNUtils.int2BN(1))
                other_factor_exponent.append(0)
                self_pass = False
                ret_exponent.append(y_exponent)
            else:
                self_factor.append(BNUtils.int2BN(1))
                self_factor_exponent.append(0)
                other_factor.append(BNUtils.int2BN(1))
                other_factor_exponent.append(0)
                ret_exponent.append(x_exponent)

        if not self_pass:
            self_factor_ippEncryptedNumber = ipclEncryptedNumber(
                self.public_key.pubkey, self_factor
            )
            self_ippEncryptedNumber_factored = (
                x * self_factor_ippEncryptedNumber
            )
        else:
            self_ippEncryptedNumber_factored = x

        if not other_pass:
            other_factor_ippEncryptedNumber = ipclEncryptedNumber(
                self.public_key.pubkey, other_factor
            )
            other_ippEncryptedNumber_factored = (
                y * other_factor_ippEncryptedNumber
            )
        else:
            other_ippEncryptedNumber_factored = y

        return (
            self_ippEncryptedNumber_factored,
            other_ippEncryptedNumber_factored,
            ret_exponent,
        )

    def increase_exponent_to(
        self,
        x: ipclEncryptedNumber,
        x_expo: Union[np.ndarray, list],
        exponent: int,
    ) -> ipclEncryptedNumber:
        """
        Increases exponent of py_ipp_paillier.PaillierEncryptedNumber
        to target exponent
        Args:
            x: py_ipp_paillier.PaillierEncryptedNumber
            x_expo: list of exponents of x
            exponent: target exponent. Needs to be larger than current exponent
        Returns:
            Updated encrypted number with increased exponent
        """

        self_factor = []
        self_factor_exponent = []
        self_pass = True

        for x_exponent in x_expo:
            if x_exponent > exponent:
                raise ValueError(
                    "Target exponent must be larger" " than exponents of x"
                )
            elif x_exponent == exponent:
                self_factor.append(BNUtils.int2BN(1))
                self_factor_exponent.append(0)
            else:
                self_factor.append(
                    BNUtils.int2BN(
                        pow(FixedPointNumber.BASE, exponent - x_exponent)
                    )
                )
                self_factor_exponent.append(exponent - x_exponent)
                self_pass = False

        if not self_pass:
            self_factor_ippEncryptedNumber = ipclEncryptedNumber(
                self.public_key.pubkey, self_factor
            )
            self_ippEncryptedNumber_factored = (
                x * self_factor_ippEncryptedNumber
            )
        else:
            self_ippEncryptedNumber_factored = x

        return self_ippEncryptedNumber_factored

    def length(self) -> int:
        return self.length

    def getExponents(self, idx: Optional[int] = None):
        if idx is None:  # get all
            return self.exponents

        chunk_id = int(idx / 8)
        portion = idx & 7
        return self.exponents[chunk_id][portion]


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
