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

TEST_ROUNDS = 10
TRACE_ROUNDS = 100

print("Initializing system environment...")
kgc = KGC()
tma = TMA()
Y_T = tma.trace_public_YT

car1 = CarA()
car2 = CarA()

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

pid1 = car1.extract_pseudonym_from_pool()
pid2 = car2.extract_pseudonym_from_pool()
skp1, omg1 = car1.generate_session_key_and_sign(pid1)
skp2, omg2 = car2.generate_session_key_and_sign(pid2)
test_msg = "V2V safety message: accident ahead, slow down".encode("utf-8")
pkg = car1.car_signcrypt(test_msg, omg2, Y_T)

test_pk = bytes_to_ubyte_ptr(omg2["pk_kem"])
test_sk = bytes_to_ubyte_ptr(skp2["sk_kem"])
test_spk = omg2["pk_sig"]
test_ssk = skp2["sk_sig"]
test_sign_msg = test_msg * 2

def avg_time(func, rounds=TEST_ROUNDS):
    total = 0.0
    for _ in range(rounds):
        s = time.perf_counter()
        func()
        e = time.perf_counter()
        total += (e - s)
    return (total / rounds) * 1000

print("")
print("=" * 70)
print("Table 1: Signcryption / Verification Breakdown (unit: ms)")
print("=" * 70)

def kem_encap():
    ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    lib.crypto_kem_enc(ct, k, test_pk)
kem_enc_time = avg_time(kem_encap)

def spx_sign():
    sphincs.sign(test_sign_msg, test_ssk)
spx_sign_time = avg_time(spx_sign)

def sm4_enc():
    sm4 = CryptSM4()
    sm4.set_key(os.urandom(16), SM4_ENCRYPT)
    sm4.crypt_ecb(test_msg + b'\x00' * 8)
sm4_enc_time = avg_time(sm4_enc)

def sm3_hash():
    sm3.sm3_hash(func.bytes_to_list(test_sign_msg))
sm3_time = avg_time(sm3_hash)

signcryption_total = avg_time(lambda: car1.car_signcrypt(test_msg, omg2, Y_T))
other_sign = signcryption_total - kem_enc_time - spx_sign_time - sm4_enc_time - sm3_time

def kem_decap():
    k = (ctypes.c_ubyte * CRYPTO_BYTES)()
    ct = bytes_to_ubyte_ptr(pkg["ct_kem"])
    lib.crypto_kem_dec(k, ct, test_sk)
kem_dec_time = avg_time(kem_decap)

test_sig = sphincs.sign(test_sign_msg, test_ssk)
def spx_verify():
    sphincs.verify(test_sign_msg, test_sig, test_spk)
spx_verify_time = avg_time(spx_verify)

def sm4_dec():
    sm4 = CryptSM4()
    key = os.urandom(16)
    sm4.set_key(key, SM4_ENCRYPT)
    ct = sm4.crypt_ecb(test_msg + b'\x00' * 8)
    sm4.set_key(key, SM4_DECRYPT)
    sm4.crypt_ecb(ct)
sm4_dec_time = avg_time(sm4_dec)

verify_dec_total = avg_time(lambda: car2.verify_and_decrypt(pkg, Y_T))
other_verify = verify_dec_total - kem_dec_time - spx_verify_time - sm4_dec_time - sm3_time

print(f"{'Component':<25} {'Signcryption':>12} {'Ratio':>8} | {'Verification':>14} {'Ratio':>8}")
print("-" * 70)
print(f"{'SPHINCS+ Signature':<25} {spx_sign_time:>12.2f} {spx_sign_time/signcryption_total*100:>7.1f}% | {0:>14.2f} {0:>7.1f}%")
print(f"{'SPHINCS+ Verification':<25} {0:>12.2f} {0:>7.1f}% | {spx_verify_time:>14.2f} {spx_verify_time/verify_dec_total*100:>7.1f}%")
print(f"{'LAC.KEM Encapsulation':<25} {kem_enc_time:>12.2f} {kem_enc_time/signcryption_total*100:>7.1f}% | {0:>14.2f} {0:>7.1f}%")
print(f"{'LAC.KEM Decapsulation':<25} {0:>12.2f} {0:>7.1f}% | {kem_dec_time:>14.2f} {kem_dec_time/verify_dec_total*100:>7.1f}%")
print(f"{'SM4 Enc/Dec':<25} {sm4_enc_time:>12.2f} {sm4_enc_time/signcryption_total*100:>7.1f}% | {sm4_dec_time:>14.2f} {sm4_dec_time/verify_dec_total*100:>7.1f}%")
print(f"{'SM3 Hash Operation':<25} {sm3_time:>12.2f} {sm3_time/signcryption_total*100:>7.1f}% | {sm3_time:>14.2f} {sm3_time/verify_dec_total*100:>7.1f}%")
print(f"{'Other Operations':<25} {other_sign:>12.2f} {other_sign/signcryption_total*100:>7.1f}% | {other_verify:>14.2f} {other_verify/verify_dec_total*100:>7.1f}%")
print("-" * 70)
print(f"{'Total':<25} {signcryption_total:>12.2f} {100:>7.1f}% | {verify_dec_total:>14.2f} {100:>7.1f}%")

print("")
print("=" * 70)
print("Table 2: Single Algorithm Performance (unit: ms)")
print("=" * 70)

pid_gen_time = avg_time(lambda: car1.extract_pseudonym_from_pool(), 100)
pid_verify_time = avg_time(lambda: pseudonym_verify(omg1, Y_T))
signcryption_time = signcryption_total
verify_dec_time = verify_dec_total

trace_start = time.perf_counter()
for i in range(TRACE_ROUNDS):
    tma.trace_malicious_pseudonym(pid1)
trace_end = time.perf_counter()
trace_total_time = (trace_end - trace_start) * 1000

def full_process():
    pid_a = car1.extract_pseudonym_from_pool()
    pid_b = car2.extract_pseudonym_from_pool()
    _, omg_a = car1.generate_session_key_and_sign(pid_a)
    _, omg_b = car2.generate_session_key_and_sign(pid_b)
    p = car1.car_signcrypt(test_msg, omg_b, Y_T)
    car2.verify_and_decrypt(p, Y_T)

full_total = avg_time(full_process, 5)

print(f"{'Algorithm':<30} {'Time (ms)':>12}")
print("-" * 45)
print(f"{'Pseudonym Generation':<30} {pid_gen_time:>12.2f}")
print(f"{'Pseudonym Verification':<30} {pid_verify_time:>12.2f}")
print(f"{'Signcryption':<30} {signcryption_time:>12.2f}")
print(f"{'Verification and Decryption':<30} {verify_dec_time:>12.2f}")
print(f"{'Pseudonym Tracing (n=100)':<30} {trace_total_time:>12.2f}")
print(f"{'Total Process Time':<30} {full_total:>12.2f}")

print("")
print("=" * 70)
print("Benchmark completed. Data ready for plotting.")
print("=" * 70)
