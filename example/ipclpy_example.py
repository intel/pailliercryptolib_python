#! /usr/bin/env python3

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from ipcl_python import PaillierKeypair, context, hybridControl, hybridMode
import pickle as pkl
import timeit
import sys
import numpy as np
from collections import OrderedDict


def test_encrypt_decrypt(sz=128):
    a = np.random.rand(sz) * 1000

    # encrypt a
    ct_a = pk.encrypt(a)

    # decrypt ct_a
    de_a = sk.decrypt(ct_a)

    # verify result
    print(
        f"{sys._getframe().f_code.co_name:<25} :: result = "
        f"{np.allclose(a, de_a)}"
    )


def test_addCTCT(sz=128):
    # test CT+CT and verify result
    a = np.random.rand(sz) * 1000
    b = np.random.rand(sz) * 1000

    # encrypt a, b
    ct_a = pk.encrypt(a)
    ct_b = pk.encrypt(b)

    # HE add (ct_a, ct_b)
    ct_sum_ab = ct_a + ct_b

    # decrypt ct_sum_ab
    de_sum_ab = sk.decrypt(ct_sum_ab)

    # verify result
    print(
        f"{sys._getframe().f_code.co_name:<25} :: result = "
        f"{np.allclose(a + b, de_sum_ab)}"
    )


def test_addCTPT(sz=128):
    # test CT+PT and verify result
    a = np.random.rand(sz) * 1000
    b = np.random.rand(sz) * 1000

    # encrypt a
    ct_a = pk.encrypt(a)

    # HE add (ct_a, b)
    ct_sum_ab = ct_a + b

    # decrypt ct_sum_ab
    de_sum_ab = sk.decrypt(ct_sum_ab)

    # verify result
    print(
        f"{sys._getframe().f_code.co_name:<25} :: result = "
        f"{np.allclose(a + b, de_sum_ab)}"
    )


def test_mulCTPT(sz=128):
    # test CT*PT and verify result
    a = np.random.rand(sz) * 1000
    b = np.random.rand(sz) * 1000

    # encrypt a
    ct_a = pk.encrypt(a)

    # HE multiply (ct_a, b)
    ct_mul_ab = ct_a * b

    # decrypt ct_sum_ab
    de_mul_ab = sk.decrypt(ct_mul_ab)

    # verify result
    print(
        f"{sys._getframe().f_code.co_name:<25} :: result = "
        f"{np.allclose(a * b, de_mul_ab)}"
    )


def test_HE_ops(sz=128):
    # test combination of HE ops

    a = np.random.rand(sz) * 1000
    b = np.random.rand(sz) * 1000
    c = np.random.rand(sz) * 1000

    # d is for broadcasting
    res = a - b * c

    ct_a = pk.encrypt(a)
    ct_b = pk.encrypt(b)

    ct_res = ct_a - ct_b * c

    is_allpass = True

    for i in range(5):
        # broadcasting test
        res = res + i

        ct_i = pk.encrypt(i)
        ct_res = ct_res + ct_i
        de_res = sk.decrypt(ct_res)

        if not np.allclose(res, de_res):
            is_allpass = True
            break

    print(f"{sys._getframe().f_code.co_name:<25} :: result = {is_allpass}")


def test_serialize(sz=128):
    # test pickle serialization of IPCL objects

    a = np.random.rand(sz) * 1000
    ct_a = pk.encrypt(a)

    # serialize pub key
    pkl_pk = pkl.dumps(pk)
    _pk = pkl.loads(pkl_pk)

    # serialize sec key
    pkl_sk = pkl.dumps(sk)
    _sk = pkl.loads(pkl_sk)

    # serialize PaillierEncryptedNumber
    pkl_ct_a = pkl.dumps(ct_a)
    deserialized_ct_a = pkl.loads(pkl_ct_a)
    deserialized_de_a = sk.decrypt(deserialized_ct_a)

    if not np.allclose(a, deserialized_de_a):
        print("a == deserialized_de_a  FAIL!")
        return

    # encrypt with deserialized key
    _ct_a = _pk.encrypt(a)

    # decrypt with deserialized key
    _de_a = _sk.decrypt(_ct_a)
    if not np.allclose(a, _de_a):
        print("a == _de_a  FAIL!")
        return

    print(f"{sys._getframe().f_code.co_name:<25} :: result = {True}")


def test_hybridMode(sz=64):
    # test hybridControl
    a = np.random.rand(sz) * 1000
    b = np.random.rand(sz) * 1000

    ct_a = pk.encrypt(a)

    def run_benchmark(num_iter=100):
        def bench_encrypt(x):
            _ = pk.encrypt(x)

        def bench_decrypt(ct_x):
            _ = sk.decrypt(ct_x)

        def bench_multiply(ct_x, y):
            _ = ct_x * y

        t_enc = timeit.timeit(lambda: bench_encrypt(a), number=num_iter)
        t_dec = timeit.timeit(lambda: bench_decrypt(ct_a), number=num_iter)
        t_mul = timeit.timeit(lambda: bench_multiply(ct_a, b), number=num_iter)

        return [t_enc * 1000.0, t_dec * 1000.0, t_mul * 1000.0]

    t_res = OrderedDict()

    for i in [
        hybridMode.OPTIMAL,
        hybridMode.IPP,
        hybridMode.HALF,
        hybridMode.QAT,
    ]:
        hybridControl.setHybridMode(i)
        t_res["hybridMode." + i.name] = run_benchmark(10)

    print()
    print("-- HybridMode benchmark --")
    print(
        f"{'hybridMode':<20}  {'Encrypt':<11}   {'Decrypt':<11}"
        f"   {'Multiply':<11}"
    )
    for k, v in t_res.items():
        t_enc, t_dec, t_mul = v
        print(
            f"{k:<20}  {t_enc:>3.4f} ms   {t_dec:>3.4f} ms"
            f"   {t_mul:>3.4f} ms"
        )

    print()
    print(
        "* Note: Benchmark result may not reflect full performance. For"
        " better representation, please run"
        " {PROJECT_ROOT}/bench/bench_ipcl_python.py"
    )


if __name__ == "__main__":
    print("====== IPCL-Python examples ======")
    # generate Paillier scheme key pair
    pk, sk = PaillierKeypair.generate_keypair(2048)

    # Acquire QAT engine control
    context.initializeContext("QAT")

    test_encrypt_decrypt()
    test_addCTCT()
    test_addCTPT()
    test_mulCTPT()
    test_HE_ops()
    test_serialize()
    test_hybridMode()

    # Release QAT engine control
    context.terminateContext()
