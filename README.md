# Python wrapper for Paillier Homomorphic Encryption library with Intel ipp-crypto

## Building ipp-crypto python wrapper
Build project at project root
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DIPP_PAILIER_PYTHON=ON
cmake --build build -j
```
This will generate the python module of the library. The binaries are found in ```build/python```

## Dependencies
Project PHE Python wrapper have been successfully tested on:
```
python >= 3.6
```
The following libraries are also required:
```
libmpc-dev
```
The following command will install the packages according to the configuration file ```requirements.txt```.
```bash
pip install -r requirements.txt
```

## Usage
At project root, set environment variables as:
```bash
export IPCL_PYTHON_DIR=$(pwd)
export PYTHONPATH=${IPCL_PYTHON_DIR}/build/python:${PYTHONPATH}
```

Running test script
```bash
cd python
python ipcl_python_test.py
```
