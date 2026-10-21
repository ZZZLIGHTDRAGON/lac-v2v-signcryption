import ctypes
import os
from lac_real import lib, bytes_to_ubyte_ptr, ubyte_ptr_to_bytes

# LAC-128 参数
LAC_PKE_PUBLICKEYBYTES = 896
LAC_PKE_SECRETKEYBYTES = 1792
LAC_PKE_CIPHERTEXTBYTES = 1024
LAC_KEM_SSBYTES = 32
LAC_KEM_CIPHERTEXTBYTES = 1024

print("=== 1. 测试 PKE 密钥生成 ===")
pk = (ctypes.c_ubyte * LAC_PKE_PUBLICKEYBYTES)()
sk = (ctypes.c_ubyte * LAC_PKE_SECRETKEYBYTES)()
lib.lac_pke_keypair(pk, sk)
print(f"公钥前16字节: {bytes(pk[:16]).hex()}")
print(f"私钥前16字节: {bytes(sk[:16]).hex()}")

print("\n=== 2. 测试 PKE 加密/解密 ===")
plaintext = b"test123"
mlen = len(plaintext)
m = bytes_to_ubyte_ptr(plaintext)
c = (ctypes.c_ubyte * LAC_PKE_CIPHERTEXTBYTES)()
lib.lac_pke_encrypt(c, pk, m, mlen)
print(f"密文前16字节: {bytes(c[:16]).hex()}")

decrypted = (ctypes.c_ubyte * mlen)()
lib.lac_pke_decrypt(decrypted, sk, c, LAC_PKE_CIPHERTEXTBYTES)
decrypted_bytes = bytes(decrypted)
print(f"解密结果: {decrypted_bytes}, 原始明文: {plaintext}")
print(f"是否一致: {decrypted_bytes == plaintext}")

print("\n=== 3. 测试 KEM 封装/解封装 ===")
pk_kem = (ctypes.c_ubyte * LAC_PKE_PUBLICKEYBYTES)()
sk_kem = (ctypes.c_ubyte * LAC_PKE_SECRETKEYBYTES)()
lib.lac_kem_keypair(pk_kem, sk_kem)

ct = (ctypes.c_ubyte * LAC_KEM_CIPHERTEXTBYTES)()
ss1 = (ctypes.c_ubyte * LAC_KEM_SSBYTES)()
lib.lac_kem_encapsulate(ct, ss1, pk_kem)
ss1_bytes = bytes(ss1)
print(f"封装共享密钥: {ss1_bytes.hex()}")

ss2 = (ctypes.c_ubyte * LAC_KEM_SSBYTES)()
lib.lac_kem_decapsulate(ss2, sk_kem, ct)
ss2_bytes = bytes(ss2)
print(f"解封装共享密钥: {ss2_bytes.hex()}")
print(f"是否一致: {ss1_bytes == ss2_bytes}")
