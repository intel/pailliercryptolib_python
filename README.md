# Python bindings and wrapper for Intel Paillier Cryptosystem Library
[Intel Paillier Cryptosystem Library](https://github.com/intel/pailliercryptolib) is an open-source library which provides accelerated performance of a partial homomorphic encryption (HE), named Paillier cryptosystem, by utilizing Intel® [IPP-Crypto](https://github.com/intel/ipp-crypto) technologies on Intel CPUs supporting the AVX512IFMA instructions. The library is written in modern standard C++ and provides the essential API for the Paillier cryptosystem scheme.
Intel Paillier Cryptosystem Library - Python is an Python extension module intended for Python based privacy preserving machine learning solutions which utilizes the partial HE scheme for increased protection.

## Contents
- [Python bindings and wrapper for Intel Paillier Cryptosystem Library](#python-bindings-and-wrapper-for-intel-paillier-cryptosystem-library)
  - [Contents](#content)
  - [Introduction](#introduction)
  - [Installing the package](#installing-the-package)
    - [Requirements](#dependencies)
    - [Dependencies](#dependencies)
    - [Installation](#installation)
  - [Usage](#usage)
- [Contributors](#contributors)

## Introduction
adding intro - match front end

## Installing the package
### Requirements
In order to install and use the extension module, the system must support the AVX512IFMA instruction set, which is enabled in Intel Icelake or higher generation CPUs.
The extension runs on Python3, more specifically:
```
python>=3.6.9
pip>=22.0.1
```

### Dependencies
Must have dependencies include:
```
cmake >=3.15.1
git
pthread
g++ >= 7.0 or clang >= 10.0
```
The following libraries are also required,
```
nasm>=2.15
OpenSSL
```
which can be installed by:
```bash
sudo apt update
sudo apt install libssl-dev
```
For ```nasm```, please refer to the [Netwide Assembler webpage](https://nasm.us/) for installation details.

### Installation
Compiling and installing the extension can be done by:
```bash
python setup.py install
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

# Contributors
Main contributors to this project, sorted by alphabetical order of last name are:
  - [Sejun Kim](https://github.com/skmono) (lead)
  - [Bin Wang](https://github.com/bwang30)
