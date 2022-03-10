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
        if isinstance(value, str) or isinstance(value, complex):
            raise ValueError("input value(s) should be integer or float")
        if isinstance(value, list) or isinstance(value, np.ndarray):
            ret = []

            def chunker(seq, sz):
                for pos in range(0, len(seq), sz):
                    yield seq[pos : pos + sz]

            for chunk in chunker(value, 8):
                enc, expo = [], []
                for val in chunk:
                    if not (isinstance(val, (int, float, np.integer))):
                        raise ValueError(
                            "input value(s) should be integer or float"
                        )
                    encoding = FixedPointNumber.encode(
                        val, self.n, self.max_int
                    )
                    enc.append(BNUtils.int2BN(encoding.encoding))
                    expo.append(encoding.exponent)

                ct = self.pubkey.raw_encrypt_buff8(enc, apply_obfuscator)
                ret += [
                    PaillierEncryptedNumber(
                        self,
                        ipclEncryptedNumber(self.pubkey, _ct),
                        _expo,
                    )
                    for _ct, _expo in zip(ct, expo)
                ]
            return np.array(ret)
        else:
            encoding = FixedPointNumber.encode(value, self.n, self.max_int)
            return PaillierEncryptedNumber(
                self,
                self.pubkey.encrypt(
                    BNUtils.int2BN(encoding.encoding), apply_obfuscator
                ),
                encoding.exponent,
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
        encrypted_number: Union[np.ndarray, list, "PaillierEncryptedNumber"],
    ):
        """
        Decrypts single or list/array of PaillierEncryptedNumber

        Args:
            encrypted_number: single or list/array of PaillierEncryptedNumber

        Returns:
            array or single BigNumber of decrypted encrypted_number
        """
        if isinstance(encrypted_number, list) or isinstance(
            encrypted_number, np.ndarray
        ):
            ret = []

            def chunker(seq, sz):
                for pos in range(0, len(seq), sz):
                    yield seq[pos : pos + sz]

            for chunk in chunker(encrypted_number, 8):
                ct = []
                expo = []
                for val in chunk:
                    if not (isinstance(val, PaillierEncryptedNumber)):
                        raise ValueError(
                            "List/array must contain PaillierEncryptedNumbers"
                        )
                    if val.public_key != self.public_key:
                        raise ValueError("Public key mismatch")
                    ct.append(val.ciphertext())
                    expo.append(val.exponent)
                dec = self.prikey.raw_decrypt_buff8(ct)
                encoded = [
                    FixedPointNumber(
                        BNUtils.BN2int(_dec),
                        _expo,
                        self.public_key.n,
                        self.public_key.max_int,
                    )
                    for _dec, _expo in zip(dec, expo)
                ]
                ret += [enc.decode() for enc in encoded]
            return np.array(ret)
        else:
            # check pubkey match
            if encrypted_number.public_key != self.public_key:
                raise ValueError("Public key mismatch")
            encoded = FixedPointNumber(
                BNUtils.BN2int(
                    self.prikey.raw_decrypt(encrypted_number.ciphertext())
                ),
                encrypted_number.exponent,
                self.public_key.n,
                self.public_key.max_int,
            )
            dtval = encoded.decode()
            return dtval


class PaillierEncryptedNumber(object):
    def __init__(
        self,
        public_key: PaillierPublicKey,
        ciphertext: ipclEncryptedNumber,
        exponent: int = 0,
    ):
        """
        PaillierEncryptedNumber constructor

        Args:
            public_key: PaillierPublicKey
            ciphertext: ipcl_bindings.PaillierEncryptedNumber
            exponent: exponent of ciphertext
        """
        if not isinstance(ciphertext, ipclEncryptedNumber):
            raise ValueError(str(type(ciphertext)) + " is unsupported")

        self.exponent = exponent
        self.public_key = public_key
        self.ippEncryptedNumber = ciphertext
        self.__ciphertext = self.ippEncryptedNumber.getBN()

    def __repr__(self):
        return self.ippEncryptedNumber.__repr__()

    def __getstate__(self):
        return (self.public_key, self.exponent, self.__ciphertext)

    def __setstate__(self, state: tuple):
        self.public_key, self.exponent, self.__ciphertext = state
        self.ippEncryptedNumber = ipclEncryptedNumber(
            self.public_key.pubkey, self.__ciphertext
        )

    def ciphertext(self):
        """
        Getter function for obfuscated ciphertext

        Returns:
            Ciphertext in BigNumber datatype
        """
        return self.ippEncryptedNumber.getBN()

    def __add__(self, other) -> "PaillierEncryptedNumber":
        return self.__raw_add(other)

    def __radd__(self, other) -> "PaillierEncryptedNumber":
        return self.__add__(other)

    def __sub__(self, other) -> "PaillierEncryptedNumber":
        return self.__raw_add(other * -1)

    def __rsub__(self, other) -> "PaillierEncryptedNumber":
        return self.__sub__(other)

    def __rmul__(self, other) -> "PaillierEncryptedNumber":
        return self.__mul__(other)

    def __truediv__(self, scalar) -> "PaillierEncryptedNumber":
        return self.__mul__(1 / scalar)

    def __mul__(self, scalar: Union[float, int]) -> "PaillierEncryptedNumber":
        encode = FixedPointNumber.encode(
            scalar, self.public_key.n, self.public_key.max_int
        )
        pt = encode.encoding

        if pt < 0 or pt >= self.public_key.n:
            raise ValueError("Scalar out of bounds: %i" % pt)

        if pt >= self.public_key.n - self.public_key.max_int:
            neg_c = gmpy2.invert(
                BNUtils.BN2int(self.ciphertext()), self.public_key.nsquare
            )
            neg_ciphertext = BNUtils.int2BN(neg_c)
            neg_ippEncryptedNumber = ipclEncryptedNumber(
                self.public_key.pubkey, neg_ciphertext
            )
            neg_scalar = self.public_key.n - pt
            ct = neg_ippEncryptedNumber * BNUtils.int2BN(neg_scalar)
        else:
            ct = self.ippEncryptedNumber * BNUtils.int2BN(pt)

        exponent = self.exponent + encode.exponent

        return PaillierEncryptedNumber(self.public_key, ct, exponent)

    def __raw_add(
        self, other: Union["PaillierEncryptedNumber", int, float]
    ) -> "PaillierEncryptedNumber":
        if isinstance(other, PaillierEncryptedNumber):
            # check key match for ct+ct
            if self.public_key != other.public_key:
                raise ValueError("Public key mismatch")
            self, other = self.__align_exponent(self, other)
            res = self.ippEncryptedNumber + other.ippEncryptedNumber
            return PaillierEncryptedNumber(self.public_key, res, self.exponent)
        elif isinstance(other, (int, np.integer, float)):
            other_ct = self.public_key.encrypt(other, apply_obfuscator=False)
            self, other_ct = self.__align_exponent(self, other_ct)

            res = self.ippEncryptedNumber + other_ct.ippEncryptedNumber

            return PaillierEncryptedNumber(self.public_key, res, self.exponent)
        else:
            raise TypeError(
                "Invalid input - Integer or"
                "PaillierEncryptedNumber type allowed"
            )

    def increase_exponent_to(self, exponent: int) -> "PaillierEncryptedNumber":
        """
        Increases exponent of ciphertext to target exponent

        Args:
            exponent: target exponent. Needs to be larger than current exponent

        Returns:
            Updated PaillierEncryptedNumber with increased exponent
        """
        if exponent < self.exponent:
            raise ValueError(
                "New exponent %i should be greater than old exponent %i"
                % (exponent, self.exponent)
            )

        factor = pow(FixedPointNumber.BASE, exponent - self.exponent)
        new_encryptednumber = self.__mul__(factor)
        new_encryptednumber.exponent = exponent

        return new_encryptednumber

    def __align_exponent(
        self, x: "PaillierEncryptedNumber", y: "PaillierEncryptedNumber"
    ) -> Tuple["PaillierEncryptedNumber", "PaillierEncryptedNumber"]:
        """
        Aligns exponent of two PaillierEncryptedNumbers

        Returns:
            tuple of pair of exponent matching PaillierEncryptedNumber
        """
        if x.exponent < y.exponent:
            x = x.increase_exponent_to(y.exponent)
        elif x.exponent > y.exponent:
            y = y.increase_exponent_to(x.exponent)

        return x, y


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
