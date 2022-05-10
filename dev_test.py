import ipcl_python as ipp
import numpy as np
import pickle as cpkl


def test_encdec(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    ct_x = pk.encrypt(x)
    dt_x = sk.decrypt(ct_x)
    print("test_encdec: ", np.allclose(x, dt_x))


def test_addctct(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    y = np.random.rand(sz) * 100
    z = x + y

    ct_x = pk.encrypt(x)
    ct_y = pk.encrypt(y)
    ct_z = ct_x + ct_y

    dt_z = sk.decrypt(ct_z)

    print("test_addctct: ", np.allclose(z, dt_z))


def test_addctpt(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    y = np.random.rand(sz) * 100
    z = x + y

    ct_x = pk.encrypt(x)
    ct_z = ct_x + y

    dt_z = sk.decrypt(ct_z)

    print("test_addctpt: ", np.allclose(z, dt_z))


def test_mulctpt(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    y = np.random.rand(sz) * 100
    z = x * y

    ct_x = pk.encrypt(x)
    ct_z = ct_x * y

    dt_z = sk.decrypt(ct_z)

    print("test_mulctpt: ", np.allclose(z, dt_z))


def test_mulctzeropt(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    y = 0
    z = x * y

    ct_x = pk.encrypt(x)
    ct_z = ct_x * y

    dt_z = sk.decrypt(ct_z)

    print("test_mulctzeropt: ", np.allclose(z, dt_z))


def test_sum(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    z = sum(x)

    ct_x = pk.encrypt(x)
    ct_z = ct_x.sum()

    dt_z = sk.decrypt(ct_z)
    print(z, dt_z)
    print("test_sum: ", np.allclose(z, dt_z))


def test_mean(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    z = np.mean(x)

    ct_x = pk.encrypt(x)
    ct_z = ct_x.mean()

    dt_z = sk.decrypt(ct_z)
    print("test_MEAN: ", np.allclose(z, dt_z))


def test_dot(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    y = np.random.rand(sz) * 100
    z = np.dot(x, y)

    ct_x = pk.encrypt(x)
    ct_z = ct_x.dot(y)

    dt_z = sk.decrypt(ct_z)
    print("test_dot: ", np.allclose(z, dt_z))


def test_pkl(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = np.random.rand(sz) * 100
    ct_x = pk.encrypt(x)

    bpk = cpkl.dumps(pk)
    _pk = cpkl.loads(bpk)

    _x1 = sk.decrypt(_pk.encrypt(x))
    print("pkl pubkey: ", np.allclose(x, _x1))

    bsk = cpkl.dumps(sk)
    _sk = cpkl.loads(bsk)

    _x2 = _sk.decrypt(ct_x)
    print("pkl seckey: ", np.allclose(x, _x2))

    bct_x = cpkl.dumps(ct_x)
    _ct_x = cpkl.loads(bct_x)
    _x3 = _sk.decrypt(_ct_x)
    print("pkl ct_x: ", np.allclose(x, _x3))


def test_mul():
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    x = 9
    en_x = pk.encrypt(x)

    for _ in range(100):
        en_x = en_x + 5000
        en_x = en_x - 0.2
        x = x + 5000 - 0.2

        de_en_x = sk.decrypt(en_x)

        print(de_en_x, x)


def test_sub(sz=150):
    pk, sk = ipp.PaillierKeypair.generate_keypair(2048)

    # x = np.random.rand(sz)*100
    # y = np.random.rand(sz)*100
    # z = x - y
    x = 9
    z = x + 5000 - 1

    ct_x = pk.encrypt(x)
    # ct_y = pk.encrypt(y)
    ct_z = ct_x + 5000 - 1

    dt_z = sk.decrypt(ct_z)

    print("test_sub: ", np.allclose(z, dt_z))


if __name__ == "__main__":
    # test_encdec()
    # test_addctct()
    # test_addctpt()
    # test_mulctpt()
    # test_mulctzeropt()
    # test_sum(256)
    # test_mean()
    # test_dot()
    # test_pkl()
    # test_mul()
    test_sub()
