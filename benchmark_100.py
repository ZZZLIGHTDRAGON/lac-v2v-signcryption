import time
import os
import ctypes
from lac_car_kgc import CarA, KGC, TMA, pseudonym_verify
from lac_real import (
    lib, bytes_to_ubyte_ptr, ubyte_ptr_to_bytes,
    CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES
)
import pyspx.shake_128f as sphincs
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func

# ========== 测试轮数配置 ==========
HEAVY_ROUNDS = 100    # 重操作跑100次取平均
LIGHT_ROUNDS = 1000   # 轻操作跑1000次取平均
TRACE_ROUNDS = 100    # 追踪100次，与图表一致
FULL_ROUNDS = 20      # 完整流程跑20次

# ========== 环境初始化 ==========
print("[1/3] Initializing system environment...")
kgc = KGC()
tma = TMA()
Y_T = tma.trace_public_YT

car1 = CarA()
car2 = CarA()

# 完成完整注册
car1_temp_pk = car1.lac_generate_temp_keypair()
enc1, raw1 = kgc.generate_partial_key(car1_temp_pk)
K1 = car1.lac_decrypt_K(enc1)
W1, C1 = tma.car_register(car1.real_id, car1.w_i, K1)
car1.generate_long_term_state_and_pool(K1, W1, C1)

car2_temp_pk = car2.lac_generate_temp_keypair()
enc2, raw2 = kgc.generate_partial_key(car2_temp_pk)
K2 = car2.lac_decrypt_K(enc2)
W2, C2 = tma.car_register(car2.real_id, car2.w_i, K2)
car2.generate_long_term_state_and_pool(K2, W2, C2)

# 预生成假名与会话
pid1 = car1.extract_pseudonym_from_pool()
pid2 = car2.extract_pseudonym_from_pool()
skp1, omg1 = car1.generate_session_key_and_sign(pid1)
skp2, omg2 = car2.generate_session_key_and_sign(pid2)
test_msg = "V2V safety message: accident ahead, slow down".encode("utf-8")
pkg = car1.car_signcrypt(test_msg, omg2, Y_T)

# 组件测试素材
test_pk = bytes_to_ubyte_ptr(omg2["pk_kem"])
test_sk = bytes_to_ubyte_ptr(skp2["sk_kem"])
test_spk = omg2["pk_sig"]
test_ssk = skp2["sk_sig"]
test_sign_msg = test_msg * 2
test_sig = sphincs.sign(test_sign_msg, test_ssk)

# ========== 计时工具函数 ==========
def avg_time(func, rounds):
    total = 0.0
    for _ in range(rounds):
        s = time.perf_counter()
        func()
        e = time.perf_counter()
        total += (e - s)
    return (total / rounds) * 1000

# ========== 第一部分：组件耗时分解（对应图1） ==========
print("[2/3] Running component breakdown benchmark...")

# --- 签密侧 ---
def kem_encap():
    ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    lib.crypto_kem_enc(ct, k, test_pk)
t_kem_enc = avg_time(kem_encap, HEAVY_ROUNDS)

def spx_sign():
    sphincs.sign(test_sign_msg, test_ssk)
t_spx_sign = avg_time(spx_sign, HEAVY_ROUNDS)

def sm4_enc():
    sm4 = CryptSM4()
    sm4.set_key(os.urandom(16), SM4_ENCRYPT)
    sm4.crypt_ecb(test_msg + b'\x00' * 8)
t_sm4_enc = avg_time(sm4_enc, LIGHT_ROUNDS)

def sm3_hash():
    sm3.sm3_hash(func.bytes_to_list(test_sign_msg))
t_sm3 = avg_time(sm3_hash, LIGHT_ROUNDS)

t_sign_total = avg_time(lambda: car1.car_signcrypt(test_msg, omg2, Y_T), HEAVY_ROUNDS)
t_other_sign = t_sign_total - t_kem_enc - t_spx_sign - t_sm4_enc - t_sm3

# --- 验证解密侧 ---
def kem_decap():
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    ct = bytes_to_ubyte_ptr(pkg["ct_kem"])
    lib.crypto_kem_dec(k, ct, test_sk)
t_kem_dec = avg_time(kem_decap, HEAVY_ROUNDS)

def spx_verify():
    sphincs.verify(test_sign_msg, test_sig, test_spk)
t_spx_verify = avg_time(spx_verify, HEAVY_ROUNDS)

def sm4_dec():
    sm4 = CryptSM4()
    key = os.urandom(16)
    sm4.set_key(key, SM4_ENCRYPT)
    ct = sm4.crypt_ecb(test_msg + b'\x00' * 8)
    sm4.set_key(key, SM4_DECRYPT)
    sm4.crypt_ecb(ct)
t_sm4_dec = avg_time(sm4_dec, LIGHT_ROUNDS)

t_verify_total = avg_time(lambda: car2.verify_and_decrypt(pkg, Y_T), HEAVY_ROUNDS)
t_other_verify = t_verify_total - t_kem_dec - t_spx_verify - t_sm4_dec - t_sm3

# ========== 第二部分：单算法总耗时（对应图2） ==========
print("[3/3] Running single algorithm benchmark...")

# 修复：假名生成测试前重置指针，循环使用池
def test_pid_gen():
    if car1.pool_pointer >= len(car1.state_pool):
        car1.pool_pointer = 0
    car1.extract_pseudonym_from_pool()
t_pid_gen = avg_time(test_pid_gen, LIGHT_ROUNDS)

t_pid_verify = avg_time(lambda: pseudonym_verify(omg1, Y_T), HEAVY_ROUNDS)
t_signcryption = t_sign_total
t_verify_dec = t_verify_total

# 假名追踪 n=100
trace_s = time.perf_counter()
for i in range(TRACE_ROUNDS):
    tma.trace_malicious_pseudonym(pid1)
trace_e = time.perf_counter()
t_trace_100 = (trace_e - trace_s) * 1000

# 完整流程总时间
def full_process():
    if car1.pool_pointer >= len(car1.state_pool):
        car1.pool_pointer = 0
    if car2.pool_pointer >= len(car2.state_pool):
        car2.pool_pointer = 0
    pid_a = car1.extract_pseudonym_from_pool()
    pid_b = car2.extract_pseudonym_from_pool()
    _, omg_a = car1.generate_session_key_and_sign(pid_a)
    _, omg_b = car2.generate_session_key_and_sign(pid_b)
    p = car1.car_signcrypt(test_msg, omg_b, Y_T)
    car2.verify_and_decrypt(p, Y_T)
t_full = avg_time(full_process, FULL_ROUNDS)

# ========== 打印结果 ==========
print("\n" + "=" * 80)
print("Table 1: Component Breakdown (for Figure 1)  Unit: ms")
print("=" * 80)
print(f"{'Component':<25} | {'Signcryption':>14} {'Proportion':>12} | {'Verification':>14} {'Proportion':>12}")
print("-" * 80)
print(f"{'SPHINCS+ Signature':<25} | {t_spx_sign:>14.2f} {t_spx_sign/t_sign_total*100:>11.1f}% | {0:>14.2f} {0:>11.1f}%")
print(f"{'SPHINCS+ Verification':<25} | {0:>14.2f} {0:>11.1f}% | {t_spx_verify:>14.2f} {t_spx_verify/t_verify_total*100:>11.1f}%")
print(f"{'LAC.KEM Encapsulation':<25} | {t_kem_enc:>14.2f} {t_kem_enc/t_sign_total*100:>11.1f}% | {0:>14.2f} {0:>11.1f}%")
print(f"{'LAC.KEM Decapsulation':<25} | {0:>14.2f} {0:>11.1f}% | {t_kem_dec:>14.2f} {t_kem_dec/t_verify_total*100:>11.1f}%")
print(f"{'SM4 Enc/Dec':<25} | {t_sm4_enc:>14.2f} {t_sm4_enc/t_sign_total*100:>11.1f}% | {t_sm4_dec:>14.2f} {t_sm4_dec/t_verify_total*100:>11.1f}%")
print(f"{'SM3 Hash Operation':<25} | {t_sm3:>14.2f} {t_sm3/t_sign_total*100:>11.1f}% | {t_sm3:>14.2f} {t_sm3/t_verify_total*100:>11.1f}%")
print(f"{'Other Operations':<25} | {t_other_sign:>14.2f} {t_other_sign/t_sign_total*100:>11.1f}% | {t_other_verify:>14.2f} {t_other_verify/t_verify_total*100:>11.1f}%")
print("-" * 80)
print(f"{'Total':<25} | {t_sign_total:>14.2f} {100:>11.1f}% | {t_verify_total:>14.2f} {100:>11.1f}%")

print("\n" + "=" * 80)
print("Table 2: Single Algorithm Performance (for Figure 2)  Unit: ms")
print("=" * 80)
print(f"{'Algorithm':<32} {'Time (ms)':>12}")
print("-" * 45)
print(f"{'Pseudonym Generation':<32} {t_pid_gen:>12.2f}")
print(f"{'Pseudonym Verification':<32} {t_pid_verify:>12.2f}")
print(f"{'Signcryption':<32} {t_signcryption:>12.2f}")
print(f"{'Verification and Decryption':<32} {t_verify_dec:>12.2f}")
print(f"{'Pseudonym Tracing (n=100)':<32} {t_trace_100:>12.2f}")
print(f"{'Total Process Time':<32} {t_full:>12.2f}")

print("\n" + "=" * 80)
print(f"Benchmark finished. Heavy ops averaged over {HEAVY_ROUNDS} runs.")
print("All data can be directly used to plot your two figures.")
print("=" * 80)
