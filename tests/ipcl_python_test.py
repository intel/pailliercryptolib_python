# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import numpy as np
import unittest
from ipcl_python.ipcl_python import PaillierKeypair
import time


class TestPaillierEncryptedNumber(unittest.TestCase):
    def setUp(self):
        self.public_key, self.private_key = PaillierKeypair.generate_keypair(
            2048
        )
        self.startTime = time.perf_counter()

    def tearDown(self):
        t = time.perf_counter() - self.startTime
        print("%s: %.3f" % (self.id(), t))

    def test_add(self):
        np.set_printoptions(suppress=True)
        x_li = np.ones(100) * np.random.randint(100)
        y_li = np.ones(100) * np.random.randint(1000)
        z_li = np.ones(100) * np.random.rand()
        t_li = list(range(100))
        en_x_li = self.public_key.encrypt(x_li)
        en_y_li = self.public_key.encrypt(y_li)
        en_z_li = self.public_key.encrypt(z_li)
        en_t_li = self.public_key.encrypt(t_li)

        en_res = en_x_li + en_y_li + en_z_li + en_t_li

        res = x_li + y_li + z_li + t_li
        de_en_res = self.private_key.decrypt(en_res)

        for i in range(x_li.shape[0]):
            self.assertAlmostEqual(de_en_res[i], res[i])

    def test_mul(self):
        np.set_printoptions(suppress=True)
        x_li = np.ones(100) * np.random.randint(100)
        y_li = np.ones(100) * np.random.randint(1000) * -1
        z_li = np.ones(100) * np.random.rand()
        t_li = list(range(100))

        en_x_li = self.public_key.encrypt(x_li)
        en_res = (en_x_li * y_li + z_li) * t_li
        de_en_res = self.private_key.decrypt(en_res)

        res = (x_li * y_li + z_li) * t_li

        for i in range(x_li.shape[0]):
            self.assertAlmostEqual(de_en_res[i], res[i])

        x = 9
        en_x = self.public_key.encrypt(x)

        for i in range(100):
            en_x = en_x + 5000
            en_x = en_x - 0.2
            x = x + 5000 - 0.2

            de_en_x = self.private_key.decrypt(en_x)

            self.assertAlmostEqual(de_en_x, x)

    def test_matmul(self):
        np.set_printoptions(suppress=True)
        for _ in range(10):
            m = np.random.randint(1, 9)
            n = np.random.randint(1, 9)
            k = np.random.randint(1, 9)
            x_li = np.random.rand(m, n)
            y_li = np.random.rand(n, k)

            res = x_li @ y_li

            en_x_li = self.public_key.encrypt(x_li.flatten())
            en_res = en_x_li.matmul(y_li)
            de_en_res = self.private_key.decrypt(en_res)
            de_en_res = np.array(de_en_res).reshape([m, k])

            np.allclose(de_en_res, res)

    def test_rmatmul_f(self):
        np.set_printoptions(suppress=True)
        for _ in range(10):
            m = np.random.randint(1, 9)
            n = np.random.randint(1, 9)
            k = np.random.randint(1, 9)
            x_li = np.random.rand(m, n)
            y_li = np.random.rand(n, k)

            res = x_li @ y_li

            en_y_li = self.public_key.encrypt(y_li.flatten())
            en_res = en_y_li.rmatmul_f(x_li)
            de_en_res = self.private_key.decrypt(en_res)
            de_en_res = np.array(de_en_res).reshape([m, k])

            np.allclose(de_en_res, res)


if __name__ == "__main__":
    # unittest.main()
    suite = unittest.TestLoader().loadTestsFromTestCase(
        TestPaillierEncryptedNumber
    )
    unittest.TextTestRunner(verbosity=0).run(suite)
