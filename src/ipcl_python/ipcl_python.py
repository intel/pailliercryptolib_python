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
        return self.pubkey

    def __setstate__(self, state):
        self.pubkey = state
        self.n = BNUtils.BN2int(self.pubkey.n)
        self.max_int = self.n // 3 - 1
        self.nsquare = self.n * self.n

    def __repr__(self):
        return self.pubkey.__repr__()

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return self.pubkey.__hash__()

    def apply_obfuscator(self, x: Union[int, ipclBigNumber]):
        # apply_obfuscator function is embedded in encrypt
        if isinstance(x, int):
            return self.pubkey.apply_obfuscator(BNUtils.int2BN(x))
        return self.pubkey.apply_obfuscator(x)

    def raw_encrypt(
        self, plaintext: Union[np.ndarray, list, int, float]
    ) -> "PaillierEncryptedNumber":
        return self.encrypt(plaintext, apply_obfuscator=False)

    def encrypt(
        self,
        value: Union[np.ndarray, list, int, float],
        apply_obfuscator: bool = True,
    ) -> "PaillierEncryptedNumber":
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
                    "PaillierPublicKey.encrypt: input value(s) should be"
                    " integer or float"
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
            self.__n = BNUtils.BN2int(key.n)
            self.__max_int = self.__n // 3 - 1
            # self.public_key = PaillierPublicKey(key.public_key)
        elif isinstance(key, ipclPublicKey) and p is not None and q is not None:
            self.prikey = ipclPrivateKey(
                key, BNUtils.int2BN(p), BNUtils.int2BN(q)
            )
            self.__n = BNUtils.BN2int(key.n)
            self.__max_int = self.__n // 3 - 1
            # self.public_key = PaillierPublicKey(key)
        elif (
            isinstance(key, PaillierPublicKey)
            and p is not None
            and q is not None
        ):
            self.prikey = ipclPrivateKey(
                key.pubkey, BNUtils.int2BN(p), BNUtils.int2BN(q)
            )
            self.__n = key.n
            self.__max_int = key.max_int
        else:
            raise KeyError(
                "PaillierPrivateKey: key should be either Private key or"
                " Public key (with p and q)"
            )

    def __getstate__(self):
        return (self.prikey, self.__n, self.__max_int)

    def __setstate__(self, state):
        (self.prikey, self.__n, self.__max_int) = state

    def __eq__(self, other: "PaillierPrivateKey"):
        return (self.prikey.p == other.prikey.p) and (
            self.prikey.q == other.prikey.q
        )

    def __hash__(self):
        return self.prikey.__hash__()

    def __repr__(self):
        return self.prikey.__repr__()

    def raw_decrypt(self, ciphertext: "PaillierEncryptedNumber") -> int:
        if ciphertext.public_key.n != self.__n:
            raise ValueError(
                "PaillierPrivateKey.raw_decrypt:" "Public key mismatch"
            )

        decrypted = self.prikey.decrypt(ciphertext.ciphertext())
        l_pt = decrypted.getTexts()
        ret = [BNUtils.BN2int(i) for i in l_pt]

        return ret if len(ciphertext) > 1 else ret[0]

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
        if encrypted_number.public_key.n != self.__n:
            raise ValueError("PailierPrivateKey.decrypt: Public key mismatch")

        decrypted = self.prikey.decrypt(encrypted_number.ciphertext())
        l_pt, l_expo = decrypted.getTexts(), encrypted_number.exponent()

        ret = []
        for pt, expo in zip(l_pt, l_expo):
            dec = FixedPointNumber(
                BNUtils.BN2int(pt),
                expo,
                self.__n,
                self.__max_int,
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
            len(self),
            self.exponent(),
            [BNUtils.BN2int(i) for i in self.ciphertextBN()],
        )

    def __setstate__(self, state: tuple):
        (
            self.public_key,
            self.__length,
            self.__exponents,
            ciphertextPyInt,
        ) = state
        self.__ipclCipherText = ipclCipherText(
            self.public_key.pubkey, [BNUtils.int2BN(i) for i in ciphertextPyInt]
        )

    def __len__(self) -> int:
        return self.__length

    def ciphertext(self) -> ipclCipherText:
        return self.__ipclCipherText

    def ciphertextBN(self, idx: Optional[int] = None):
        """
        Getter function for obfuscated ciphertext
        Args:=
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

    def apply_obfuscator(self):
        self.__ipclCipherText = ipclCipherText(
            self.public_key.pubkey,
            self.public_key.pubkey.apply_obfuscator(self.__ipclCipherText),
        )

    # TODO(skmono): Enable after making it compatible with recursive_decrypt
    # def __getitem__(self, key: Union[int, slice]
    # ) -> "PaillierEncryptedNumber":
    #     if isinstance(key, slice):
    #         if (
    #             key.stop >= len(self)
    #             or key.stop < 0
    #             or key.start < 0
    #             or key.start >= len(self)
    #         ):
    #             raise IndexError("__getitem__: key out of range")
    #         ciphertextBN = [
    #             self.__ipclCipherText[i]
    #             for i in range(*key.indices(len(self)))
    #         ]
    #         newCT = ipclCipherText(self.public_key.pubkey, ciphertextBN)
    #         return PaillierEncryptedNumber(
    #             self.public_key, newCT,
    #             self.__exponents[key], len(ciphertextBN)
    #         )
    #     else:
    #         if key < 0 or key >= len(self):
    #             raise IndexError("__getitem__: key out of range")
    #         return PaillierEncryptedNumber(
    #             self.public_key,
    #             self.__ipclCipherText.getCipherText(key),
    #             [self.exponent(key)],
    #             1,
    #         )
    #
    # def __setitem__(self, *key):
    #     print("__setitem__: Not supported")
    #
    # def __iter__(self) -> "PaillierEncryptedNumber":
    #     for i in range(len(self)):
    #         yield self.__getitem__(i)

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
                            int(
                                gmpy2.invert(
                                    BNUtils.BN2int(_ct), self.public_key.nsquare
                                )
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
                            int(
                                gmpy2.invert(
                                    BNUtils.BN2int(_ct), self.public_key.nsquare
                                )
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
                raise ValueError(
                    "PaillierEncryptedNumber.__raw_add: PublicKey mismatch"
                )
            if self.__length != len(other) and len(other) > 1:
                raise ValueError(
                    "PaillierEncryptedNumber.__raw_add: CipherText size"
                    " mismatch with PaillierEncryptedNumber"
                )

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
        self,
        x_ct: ipclCipherText,
        x_expo: Union[np.ndarray, list],
        exponent: int,
    ) -> ipclCipherText:
        """
        Increases exponent of py_ipp_paillier.PaillierEncryptedNumber
        to target exponent
        Args:
            x_ct: ipclCipherText
            x_expo: list of exponents of x
            exponent: target exponent. Needs to be larger than current exponent
        Returns:
            Updated encrypted number with increased exponent
        """

        expo_diff = exponent - np.fromiter(x_expo, np.int32)
        idx_to_multiply = np.asarray(expo_diff > 0).nonzero()[0]

        if idx_to_multiply.size > 0:
            x_to_multiply, x_factor = [], []
            for i in idx_to_multiply:
                x_to_multiply.append(x_ct[i])
                x_factor.append(
                    BNUtils.int2BN(
                        pow(FixedPointNumber.BASE, expo_diff[i].item())
                    )
                )

            x_to_multiply_ipclCipherText = ipclCipherText(
                self.public_key.pubkey, x_to_multiply
            )
            x_factor_ipclPlainText = ipclPlainText(x_factor)
            x_ipclCipherText_factored = (
                x_to_multiply_ipclCipherText * x_factor_ipclPlainText
            )

            ret = np.fromiter(x_ct.getTexts(), ipclBigNumber)
            ret[idx_to_multiply] = x_ipclCipherText_factored.getTexts()

            return ipclCipherText(self.public_key.pubkey, ret.tolist())

        return x_ct

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

        x_to_multiply = []
        x_idx_to_multiply = []

        y_factor = []

        y_idx_to_multiply = []

        ret_exponent = list(x_expo)

        # if broadcasting
        if len(y_ct) == 1:
            for i, _x_expo in enumerate(x_expo):
                if _x_expo > y_expo[0]:
                    y_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, _x_expo - y_expo[0])
                        )
                    )
                    y_idx_to_multiply.append(i)
                elif _x_expo < y_expo[0]:
                    x_factor.append(
                        BNUtils.int2BN(
                            pow(FixedPointNumber.BASE, y_expo[0] - _x_expo)
                        )
                    )
                    x_idx_to_multiply.append(i)
                    x_to_multiply.append(x_ct[i])
                    ret_exponent[i] = y_expo[0]

            x_factored_CipherText = None
            if len(x_idx_to_multiply) > 0:
                x_to_multiply_ipclCipherText = ipclCipherText(
                    self.public_key.pubkey, x_to_multiply
                )
                x_factor_PlainText = ipclPlainText(x_factor)

                x_factored_CipherText_tmp = (
                    x_to_multiply_ipclCipherText * x_factor_PlainText
                )
                x_factored_CipherText = np.fromiter(
                    x_ct.getTexts(), ipclBigNumber
                )
                x_factored_CipherText[
                    x_idx_to_multiply
                ] = x_factored_CipherText_tmp.getTexts()

            y_factored_CipherText = None
            if len(y_idx_to_multiply) > 0:
                y_to_multiply_ipclCipherText = ipclCipherText(
                    self.public_key.pubkey,
                    y_ct.getTexts() * len(y_idx_to_multiply),
                )
                y_factor_PlainText = ipclPlainText(y_factor)
                y_factored_CipherText_tmp = (
                    y_to_multiply_ipclCipherText * y_factor_PlainText
                )

                y_factored_CipherText = np.repeat(y_ct.getTexts(), len(x_ct))
                y_factored_CipherText[
                    y_idx_to_multiply
                ] = y_factored_CipherText_tmp.getTexts()

            return (
                x_ct
                if x_factored_CipherText is None
                else ipclCipherText(
                    self.public_key.pubkey, x_factored_CipherText.tolist()
                ),
                y_ct
                if y_factored_CipherText is None
                else ipclCipherText(
                    self.public_key.pubkey, y_factored_CipherText.tolist()
                ),
                ret_exponent,
            )

        else:
            y_to_multiply = []

            for i, (_x_expo, _y_expo) in enumerate(zip(x_expo, y_expo)):
                if _x_expo > _y_expo:
                    y_factor.append(
                        BNUtils.int2BN(
                            int(pow(FixedPointNumber.BASE, _x_expo - _y_expo))
                        )
                    )
                    y_idx_to_multiply.append(i)
                    y_to_multiply.append(y_ct[i])
                elif _x_expo < _y_expo:
                    x_factor.append(
                        BNUtils.int2BN(
                            int(pow(FixedPointNumber.BASE, _y_expo - _x_expo))
                        )
                    )
                    x_idx_to_multiply.append(i)
                    x_to_multiply.append(x_ct[i])
                    ret_exponent[i] = _y_expo

            x_factored_CipherText = None
            if len(x_idx_to_multiply) > 0:
                x_to_multiply_ipclCipherText = ipclCipherText(
                    self.public_key.pubkey, x_to_multiply
                )
                x_factor_PlainText = ipclPlainText(x_factor)

                x_factored_CipherText_tmp = (
                    x_to_multiply_ipclCipherText * x_factor_PlainText
                )

                x_factored_CipherText = np.fromiter(
                    x_ct.getTexts(), ipclBigNumber
                )
                x_factored_CipherText[
                    x_idx_to_multiply
                ] = x_factored_CipherText_tmp.getTexts()

            y_factored_CipherText = None
            if len(y_idx_to_multiply) > 0:
                y_to_multiply_ipclCipherText = ipclCipherText(
                    self.public_key.pubkey, y_to_multiply
                )
                y_factor_PlainText = ipclPlainText(y_factor)
                y_factored_CipherText_tmp = (
                    y_to_multiply_ipclCipherText * y_factor_PlainText
                )
                y_factored_CipherText = np.fromiter(
                    y_ct.getTexts(), ipclBigNumber
                )
                y_factored_CipherText[
                    y_idx_to_multiply
                ] = y_factored_CipherText_tmp.getTexts()

            return (
                x_ct
                if x_factored_CipherText is None
                else ipclCipherText(
                    self.public_key.pubkey, x_factored_CipherText.tolist()
                ),
                y_ct
                if y_factored_CipherText is None
                else ipclCipherText(
                    self.public_key.pubkey, y_factored_CipherText.tolist()
                ),
                ret_exponent,
            )

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
            raise ValueError(
                "PaillierEncryptedNumber.dot: input size mismatch"
                " with ciphertext"
            )

        elemul = self.__mul__(other)
        return elemul.sum()


class BNUtils:
    # slice first then send array
    @staticmethod
    def int2Bytes(val: int) -> bytes:
        val_bytes = val.to_bytes(
            (val.bit_length() + 7) // 8, byteorder="little"
        )
        return val_bytes

    @staticmethod
    def bytes2Int(val: bytes) -> int:
        val_int = int.from_bytes(val, "little")
        return val_int

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

        ret_bn = ipclBigNumber(BNUtils.int2Bytes(val))
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
        ret = BNUtils.bytes2Int(val.to_bytes())
        return ret
