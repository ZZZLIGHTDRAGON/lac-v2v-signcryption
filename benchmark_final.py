
import time
import os
import ctypes
from lac_car_kgc import CarA, KGC, TMA, pseudonym_verify
from lac_real import lib, bytes_to_ubyte_ptr, ubyte_ptr_to_bytes
from lac_real import CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES
from lac_real import CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES
import pyspx.shake_128f as sphincs
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func

HEAVY_ROUNDS = 30
LIGHT_ROUNDS = 300
TRACE_ROUNDS = 100
FULL_ROUNDS = 10

print("[1/3] Initializing system...")
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

test_pk = bytes_to_ubyte_ptr(omg2["pk_kem"])
test_sk = bytes_to_ubyte_ptr(skp2["sk_kem"])
test_spk = omg2["pk_sig"]
test_ssk = skp2["sk_sig"]
test_sign_msg = test_msg * 2
test_sig = sphincs.sign(test_sign_msg, test_ssk)

def avg_time(func, rounds):
    t = 0.0
    for _ in range(rounds):
        s = time.perf_counter()
        func()
        t += time.perf_counter() - s
    return (t / rounds) * 1000

print("[2/3] Component benchmark...")

def kem_enc():
    ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    lib.crypto_kem_enc(ct, k, test_pk)
t_kem_enc = avg_time(kem_enc, HEAVY_ROUNDS)

def spx_sig():
    sphincs.sign(test_sign_msg, test_ssk)
t_spx_sig = avg_time(spx_sig, HEAVY_ROUNDS)

def sm4_e():
    sm4 = CryptSM4()
    sm4.set_key(os.urandom(16), SM4_ENCRYPT)
    sm4.crypt_ecb(test_msg + b'\x00'*8)
t_sm4_e = avg_time(sm4_e, LIGHT_ROUNDS)

def sm3_h():
    sm3.sm3_hash(func.bytes_to_list(test_sign_msg))
t_sm3 = avg_time(sm3_h, LIGHT_ROUNDS)

t_sign_total = avg_time(lambda: car1.car_signcrypt(test_msg, omg2, Y_T), HEAVY_ROUNDS)
t_other_s = t_sign_total - t_kem_enc - t_spx_sig - t_sm4_e - t_sm3

def kem_dec():
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    ct = bytes_to_ubyte_ptr(pkg["ct_kem"])
    lib.crypto_kem_dec(k, ct, test_sk)
t_kem_dec = avg_time(kem_dec, HEAVY_ROUNDS)

def spx_ver():
    sphincs.verify(test_sign_msg, test_sig, test_spk)
t_spx_ver = avg_time(spx_ver, HEAVY_ROUNDS)

def sm4_d():
    sm4 = CryptSM4()
    key = os.urandom(16)
    sm4.set_key(key, SM4_ENCRYPT)
    ct = sm4.crypt_ecb(test_msg + b'\x00'*8)
    sm4.set_key(key, SM4_DECRYPT)
    sm4.crypt_ecb(ct)
t_sm4_d = avg_time(sm4_d, LIGHT_ROUNDS)

t_verify_total = avg_time(lambda: car2.verify_and_decrypt(pkg, Y_T), HEAVY_ROUNDS)
t_other_v = t_verify_total - t_kem_dec - t_spx_ver - t_sm4_d - t_sm3

print("[3/3] Single algorithm benchmark...")

def pid_gen():
    if car1.pool_pointer >= len(car1.state_pool):
        car1.pool_pointer = 0
    car1.extract_pseudonym_from_pool()
t_pid_gen = avg_time(pid_gen, LIGHT_ROUNDS)

t_pid_ver = avg_time(lambda: pseudonym_verify(omg1, Y_T), HEAVY_ROUNDS)

trace_s = time.perf_counter()
for _ in range(TRACE_ROUNDS):
    tma.trace_malicious_pseudonym(pid1)
t_trace = (time.perf_counter() - trace_s) * 1000

def full():
    if car1.pool_pointer >= len(car1.state_pool):
        car1.pool_pointer = 0
    if car2.pool_pointer >= len(car2.state_pool):
        car2.pool_pointer = 0
    pa = car1.extract_pseudonym_from_pool()
    pb = car2.extract_pseudonym_from_pool()
    _, oa = car1.generate_session_key_and_sign(pa)
    _, ob = car2.generate_session_key_and_sign(pb)
    tma.activate(oa, ob)
    p = car1.car_signcrypt(test_msg, ob, Y_T)
    car2.verify_and_decrypt(p, Y_T)
t_full = avg_time(full, FULL_ROUNDS)

print("\n" + "="*70)
print("TABLE 5: Component Breakdown (Unit: ms)")
print("="*70)
print(f"{'Component':<22} | {'Signcrypt':>9} {'Ratio':>9} | {'Verify':>9} {'Ratio':>9}")
print("-"*70)
print(f"SPHINCS+ Signature     | {t_spx_sig:9.2f} {t_spx_sig/t_sign_total*100:8.1f}% | {0:9.2f} {0:8.1f}%")
print(f"SPHINCS+ Verification  | {0:9.2f} {0:8.1f}% | {t_spx_ver:9.2f} {t_spx_ver/t_verify_total*100:8.1f}%")
print(f"LAC.KEM Encapsulation | {t_kem_enc:9.2f} {t_kem_enc/t_sign_total*100:8.1f}% | {0:9.2f} {0:8.1f}%")
print(f"LAC.KEM Decapsulation | {0:9.2f} {0:8.1f}% | {t_kem_dec:9.2f} {t_kem_dec/t_verify_total*100:8.1f}%")
print(f"SM4-GCM Enc/Dec    | {t_sm4_e:9.2f} {t_sm4_e/t_sign_total*100:8.1f}% | {t_sm4_d:9.2f} {t_sm4_d/t_verify_total*100:8.1f}%")
print(f"SM3 Hash Operation    | {t_sm3:9.2f} {t_sm3/t_sign_total*100:8.1f}% | {t_sm3:9.2f} {t_sm3/t_verify_total*100:8.1f}%")
print(f"Other Operations     | {t_other_s:9.2f} {t_other_s/t_sign_total*100:8.1f}% | {t_other_v:9.2f} {t_other_v/t_verify_total*100:8.1f}%")
print("-"*70)
print(f"Total               | {t_sign_total:9.2f} {100:8.1f}% | {t_verify_total:9.2f} {100:8.1f}%")

print("\n" + "="*70)
print("FIGURE 5: Single Algorithm Performance (Unit: ms)")
print("="*70)
print(f"{'Algorithm':<28} {'Time(ms)':>10}")
print("-"*40)
print(f"Pseudonym Generation        {t_pid_gen:10.2f}")
print(f"Pseudonym Verification      {t_pid_ver:10.2f}")
print(f"Signcryption            {t_sign_total:10.2f}")
print(f"Verification+Decryption   {t_verify_total:10.2f}")
print(f"Pseudonym Tracing(n=100)  {t_trace:10.2f}")
print(f"Total Process Time        {t_full:10.2f}")
print("\n✅ Benchmark finished")
