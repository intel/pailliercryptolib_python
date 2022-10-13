import numpy as np
from ipcl_python import PaillierKeypair
import ipcl_python as ipcl
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
    x = P - np.arange(state.range(0)) * 5.1112834624
    while state:
        _ = pk.encrypt(x)


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Decrypt(state):
    x = P - np.arange(state.range(0)) * 5.1112834624
    ct_x = pk.encrypt(x)
    while state:
        _ = sk.decrypt(ct_x)


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Add_CTCT(state):
    x = P - np.arange(state.range(0)) * 5.1112834624
    y = np.arange(state.range(0)) * 1.095123872 + Q
    ct_x = pk.encrypt(x)
    ct_y = pk.encrypt(y)
    while state:
        _ = ct_x + ct_y


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Add_CTPT(state):
    x = P - np.arange(state.range(0)) * 5.1112834624
    ct_x = pk.encrypt(x)
    while state:
        _ = ct_x + x


@benchmark.register
@benchmark.option.unit(benchmark.kMicrosecond)
@benchmark.option.arg(16)
@benchmark.option.arg(64)
def BM_Mul_CTPT(state):
    x = P - np.arange(state.range(0)) * 5.1112834624
    y = np.arange(state.range(0)) * 1.095123872 + Q

    ct_x = pk.encrypt(x)
    while state:
        _ = ct_x * y


if __name__ == "__main__":
    # preset values
    P = int(
        "17907722236348068892950089903191692955407412936775759886364595"
        "52735277384518331167761570138552647970967958807251538217623805"
        "88199893129274771549316901998509025503556766712439571067562061"
        "82758501008605649830815202920954024506122402034968011655978902"
        "1149844414656481106116277049053335145991958168290159067444243"
    )
    Q = int(
        "15364074494048192090239748141292366255531269713338718185264182"
        "86675686268115568620066283414819003320683895025898634379074026"
        "89773240679814850328978260611055592547225724264355875488478904"
        "93257704058129319548913255512313204302948601763310613641989076"
        "0822812194551465180127077927138009701322446602892596555566791"
    )
    N = P * Q

    pk = ipcl.PaillierPublicKey(N, N.bit_length(), True)
    sk = ipcl.PaillierPrivateKey(pk, P, Q)

    benchmark.main()
