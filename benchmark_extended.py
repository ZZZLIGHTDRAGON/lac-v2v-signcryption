
import time
import os
import ctypes
import random
import string
from lac_car_kgc import CarA, KGC, TMA, pseudonym_verify_internal, H, serialize_omega
from lac_real import lib, bytes_to_ubyte_ptr, ubyte_ptr_to_bytes
from lac_real import CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES
from lac_real import CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES
import pyspx.shake_128f as sphincs
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func

def avg_time(func, rounds):
    t = 0.0
    for _ in range(rounds):
        s = time.perf_counter()
        func()
        t += time.perf_counter() - s
    return (t / rounds) * 1000

def build_large_eit(tma, N):
    for i in range(N):
        rid = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        wi = os.urandom(16)
        Ki = os.urandom(CRYPTO_BYTES)
        Xi = os.urandom(CRYPTO_BYTES)
        tma.car_register(rid, wi, Ki, Xi)

# 实验1：追踪流程组件拆解
def trace_breakdown(tma, pkg, omega, rounds=100):
    pid_test = omega["PID_i"]
    w_i_from_pid = pid_test[0][5+16:5+16+16]
    pid_hash = H(w_i_from_pid).hex()
    entry = tma.EIT_registry[pid_hash]
    
    X_test = omega["X_i"]
    test_sig = pkg["Sig_A"]
    test_spk = omega["pk_sig"]
    msg_body = pkg["ct_kem"] + pkg["c_msg"] + pkg["tag"]
    test_hash = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg_body)))

    def step_parse():
        _ = pkg["omega_A"]
        _ = pkg["omega_A"]["PID_i"]
    t_parse = avg_time(step_parse, rounds)

    def step_psm():
        pseudonym_verify_internal(omega)
    t_psm = avg_time(step_psm, rounds)

    def step_sm3():
        sm3.sm3_hash(func.bytes_to_list(msg_body))
    t_sm3 = avg_time(step_sm3, rounds)

    def step_spx():
        sphincs.verify(test_hash, test_sig, test_spk)
    t_spx = avg_time(step_spx, rounds)

    def step_ilt():
        _ = tma.EIT_registry[pid_hash]
    t_ilt = avg_time(step_ilt, rounds)

    def step_xmatch():
        _ = (entry["X_orig"] == X_test)
    t_xmatch = avg_time(step_xmatch, rounds)

    return {
        "Parse": t_parse,
        "Psm-veri": t_psm,
        "SM3 Hash": t_sm3,
        "SPHINCS+.Verify": t_spx,
        "ILT Lookup": t_ilt,
        "X Matching": t_xmatch
    }

# 实验2：追踪耗时随N规模变化
def trace_scalability(N_list, rounds=100):
    results = {}
    kgc = KGC()
    for N in N_list:
        tma = TMA()
        build_large_eit(tma, N)
        car = CarA()
        pk = car.lac_generate_temp_keypair()
        enc, _ = kgc.generate_partial_key(pk)
        K = car.lac_decrypt_K(enc)
        W, C = tma.car_register(car.real_id, car.w_i, K, car.long_term_X)
        car.generate_long_term_state_and_pool(K, W, C)
        pid = car.extract_pseudonym_from_pool()
        
        def trace_op():
            tma.trace_malicious_pseudonym(pid)
        t_total = avg_time(trace_op, rounds)
        results[N] = t_total
    return results

# 实验3：Other Operations 拆解
def other_breakdown(car, rounds=100):
    def step_binding():
        car._CarA__cls_sign(b"benchmark test binding message")
    t_binding = avg_time(step_binding, rounds)

    def step_mem():
        _ = {"omega_A": car.omega_i, "ct_kem": b"\x00"*32, "c_msg": b"\x00"*32}
        _ = serialize_omega(car.omega_i)
    t_mem = avg_time(step_mem, rounds)

    return {
        "Binding Signature Generation": t_binding,
        "Memory & Serialization": t_mem
    }

# 主程序
print("[初始化] 正在构建系统环境...")
kgc = KGC()
tma = TMA()
Y_T = tma.trace_public_YT

car1 = CarA()
car2 = CarA()

car1_temp_pk = car1.lac_generate_temp_keypair()
enc1, raw1 = kgc.generate_partial_key(car1_temp_pk)
K1 = car1.lac_decrypt_K(enc1)
W1, C1 = tma.car_register(car1.real_id, car1.w_i, K1, car1.long_term_X)
car1.generate_long_term_state_and_pool(K1, W1, C1)

car2_temp_pk = car2.lac_generate_temp_keypair()
enc2, raw2 = kgc.generate_partial_key(car2_temp_pk)
K2 = car2.lac_decrypt_K(enc2)
W2, C2 = tma.car_register(car2.real_id, car2.w_i, K2, car2.long_term_X)
car2.generate_long_term_state_and_pool(K2, W2, C2)

pid1 = car1.extract_pseudonym_from_pool()
pid2 = car2.extract_pseudonym_from_pool()
skp1, omg1 = car1.generate_session_key_and_sign(pid1)
skp2, omg2 = car2.generate_session_key_and_sign(pid2)
test_msg = b"V2V safety test message"
pkg = car1.car_signcrypt(test_msg, omg2, Y_T)

# 实验1输出
print("\n" + "="*75)
print("实验1：追踪流程组件拆解 (100次取平均，单位: ms)")
print("="*75)
bd = trace_breakdown(tma, pkg, omg1, 100)
total_bd = sum(bd.values())
print(f"{'组件':<20} {'耗时(ms)':>12} {'占比':>10}")
print("-"*45)
for k, v in bd.items():
    print(f"{k:<20} {v:>12.2f} {v/total_bd*100:>9.1f}%")
print("-"*45)
print(f"{'Total Trace':<20} {total_bd:>12.2f} {100:>9.1f}%")

# 实验2输出
print("\n" + "="*75)
print("实验2：追踪耗时随EIT规模变化 (O(1) 复杂度验证)")
print("="*75)
N_list = [100, 500, 1000, 5000, 10000]
scal = trace_scalability(N_list, 100)
print(f"{'EIT条目数 N':<15} {'追踪总耗时(ms)':>18}")
print("-"*35)
for n, t in scal.items():
    print(f"{n:<15} {t:>18.2f}")

# 实验3输出
print("\n" + "="*75)
print("实验3：TABLE 5 Other Operations 拆解 (签密侧)")
print("="*75)
other_bd = other_breakdown(car1, 100)
print(f"{'组件':<28} {'耗时(ms)':>12}")
print("-"*42)
for k, v in other_bd.items():
    print(f"{k:<28} {v:>12.2f}")
print("-"*42)
print(f"{'Other Operations 合计':<28} {sum(other_bd.values()):>12.2f}")

print("\n✅ 全部实验完成")
