import numpy as np
from ipcl_python import PaillierKeypair
import google_benchmark as benchmark


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(1024)
@benchmark.option.arg(2048)
def BM_KeyGen(state):
    while state:
        _ = PaillierKeypair.generate_keypair(state.range(0))


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Encrypt(state):
    pk, _ = PaillierKeypair.generate_keypair(2048)
    x = np.arange(state.range(0)) * 1024 + 999
    while state:
        _ = pk.encrypt(x)


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Decrypt(state):
    pk, sk = PaillierKeypair.generate_keypair(2048)
    x = np.arange(state.range(0)) * 1024 + 999
    ct_x = pk.encrypt(x)
    while state:
        _ = sk.decrypt(ct_x)


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Add_CTCT(state):
    pk, _ = PaillierKeypair.generate_keypair(2048)
    x = np.arange(state.range(0)) * 1024 + 999
    ct_x = pk.encrypt(x)
    ct_y = ct_x
    while state:
        _ = ct_x + ct_y


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Add_CTPT(state):
    pk, _ = PaillierKeypair.generate_keypair(2048)
    x = np.arange(state.range(0)) * 1024 + 999
    ct_x = pk.encrypt(x)
    while state:
        _ = ct_x + x


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Mul_CTPT(state):
    pk, _ = PaillierKeypair.generate_keypair(2048)
    x = np.arange(state.range(0)) * 1024 + 999
    ct_x = pk.encrypt(x)
    while state:
        _ = ct_x * x


if __name__ == "__main__":
    benchmark.main()
