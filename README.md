# Python bindings and wrapper for Intel Paillier Cryptosystem Library
[Intel Paillier Cryptosystem Library](https://github.com/intel/pailliercryptolib) is an open-source library which provides accelerated performance of a partial homomorphic encryption (HE), named Paillier cryptosystem, by utilizing Intel® [IPP-Crypto](https://github.com/intel/ipp-crypto) technologies on Intel CPUs supporting the AVX512IFMA instructions. The library is written in modern standard C++ and provides the essential API for the Paillier cryptosystem scheme.
Intel Paillier Cryptosystem Library - Python is a Python extension package intended for Python based privacy preserving machine learning solutions which utilizes the partial HE scheme for increased data and model protection.

## Contents
- [Python bindings and wrapper for Intel Paillier Cryptosystem Library](#python-bindings-and-wrapper-for-intel-paillier-cryptosystem-library)
  - [Contents](#content)
  - [Introduction](#introduction)
  - [Installing the package](#installing-the-package)
    - [Prerequisites](#prerequisites)
    - [Dependencies](#dependencies)
    - [Installation](#installation)
  - [Usage](#usage)
- [Contributors](#contributors)

## Introduction
Paillier cryptosystem is a probabilistic asymmetric algorithm for public key cryptography and a partial homomorphic encryption scheme which allows two types of computation:
- addition of two ciphertexts
- addition and multiplication of a ciphertext by a plaintext number

As a public key encryption scheme, Paillier cryptosystem has three stages:

 - Generate public-private key pair
 - Encryption with public key
 - Decryption with private key

For increased security, typically the key length is at least 1024 bits, but recommendation is 2048 bits or larger. To handle such large size integers, conventional implementations of the Paillier cryptosystem utilizes the GNU Multiple Precision Arithmetic Library (GMP). The essential computation of the scheme relies on the modular exponentiation, and our library takes advantage of the multi-buffer modular exponentiation function (```mbx_exp_mb8```) of IPP-Crypto library, which is enabled in AVX512IFMA instruction sets supporting SKUs, such as Intel Icelake Xeon CPUs.

The Python extension package allows ease of use of the C++ backend library. The extension provides seamless conversion from Python integer and floating point objects, which are theoretically infinite precision limited by memory size, to C++ [BigNumber type](https://www.intel.com/content/www/us/en/develop/documentation/ipp-crypto-reference/top/public-key-cryptography-functions/big-number-arithmetic.html). It also allows easier handling of arrays in ```numpy.ndarray``` or ```list``` format, for encryption, decryption and HE computations.

## Installing the package
### Prerequisites
For best performance, especially due to the multi-buffer modular exponentiation function, the Python extension is to be used on AVX512IFMA enabled systems, as listed below in Intel CPU codenames:
- Intel Cannon Lake
- Intel Ice Lake

The extension module can be used without AVX512IFMA - if the instruction set is not detected on the system, it will automatically switch to non multi-buffer modular exponentiation.

The following operating systems have been tested and deemed to be fully functional.

- Ubuntu 18.04 and higher
- Red Hat Enterprise Linux 8.1 and higher

We will keep working on adding more supported operating systems.


### Dependencies
Must have dependencies include:
```
cmake >=3.15.1
git
pthread
g++ >= 7.0 or clang >= 10.0
python >= 3.6.9
pip>=22.0.1
```
For additional dependencies regarding the C++ backend, refer to the [Intel Paillier Cryptosystem Library](https://github.com/intel-sandbox/libraries.security.cryptography.homomorphic-encryption.glade.pailliercryptolib).

### Installation
Compiling and installing the package can be done by:
```bash
python setup.py install
```
or
```bash
pip install .
```

To test the installed module,
```bash
python setup.py test
```
and the unit-test will be executed.

## Usage
The module can be imported by:
```python
import ipcl_python
```

First, the key pair needs to be generated - public key for encryption and private key for decryption.
```python
from ipcl_python import PaillierKeypair
pubkey, prikey = PaillierKeypair.generate_keypair(2048, True)
```

For encryption and decryption, and the result verification:
```python
a = np.random.rand(100)
ct_a = pubkey.encrypt(a)

de_a = prikey.decrypt(ct_a)
print(np.allclose(a, de_a))
```

Paillier cryptosystem supports ciphertext addition and plaintext addition/multiplcation.

```python
# ciphertext addition
b = np.random.rand(100)
ct_b = pubkey.encrypt(b)
ct_c = ct_a + ct_b

de_c = prikey.decrypt(ct_c)
print(np.allclose(a + b, de_c))
```

```python
# plaintext addition
ct_c = ct_a + b

de_c = prikey.decrypt(ct_c)
print(np.allclose(a + b, de_c))
```

```python
# plaintext multiplication
ct_d = ct_a * b

de_d = prikey.decrypt(ct_d)
print(np.allclose(a * b, de_d))
```

For more details, please refer to [documentation (TBD)](https://github.com/intel/pailliercryptolib-python).

# Standardization
This library is in compliance with the homomorphic encryption standards [ISO/IEC 18033-6](https://www.iso.org/standard/67740.html).
The compliance test is included in the C++ backend [unit-test](https://github.com/intel-sandbox/libraries.security.cryptography.homomorphic-encryption.glade.pailliercryptolib/blob/main/test/test_cryptography.cpp#L117-L258).
# Contributors
Main contributors to this project, sorted by alphabetical order of last name are:
  - [Xiaojun Huang](https://github.com/xhuan28)
  - [Sejun Kim](https://github.com/skmono) (lead)
  - [Bin Wang](https://github.com/bwang30)
