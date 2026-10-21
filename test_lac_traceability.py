import unittest
import ctypes
from lac_real import (
    lib,
    bytes_to_ubyte_ptr,
    ubyte_ptr_to_bytes,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_BYTES
)

class TestLACTraceability(unittest.TestCase):
    """
    基于 LAC 格密码的车联网伪名方案 TMA 可追溯性测试
    验证：伪名密钥生成、部分密钥 K_i 加密/解密、可追溯性验证
    """

    def test_pseudonym_key_generation_and_ki_encryption(self):
        """测试车联网伪名密钥生成 + 部分密钥 K_i 加密/解密"""
        # 1. 生成车辆伪名密钥对（基于 LAC PKE）
        pk_vehicle = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_vehicle = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        ret = lib.crypto_encrypt_keypair(pk_vehicle, sk_vehicle)
        self.assertEqual(ret, 0, "车辆伪名密钥生成失败")

        # 2. 生成部分密钥 K_i（32字节随机数，用于伪名派生）
        import os
        k_i = os.urandom(32)
        k_i_ptr = bytes_to_ubyte_ptr(k_i)

        # 3. 用车辆公钥加密 K_i（LAC PKE 加密）
        ct_k_i = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        clen = ctypes.c_ulonglong(0)
        ret = lib.crypto_encrypt(ct_k_i, ctypes.byref(clen), k_i_ptr, 32, pk_vehicle)
        self.assertEqual(ret, 0, "部分密钥 K_i 加密失败")

        # 4. 用车辆私钥解密 K_i（LAC PKE 解密）
        dec_k_i = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        dec_len = ctypes.c_ulonglong(0)
        ret = lib.crypto_encrypt_open(dec_k_i, ctypes.byref(dec_len), ct_k_i, clen.value, sk_vehicle)
        self.assertEqual(ret, 0, "部分密钥 K_i 解密失败")

        # 5. 验证 K_i 解密正确性（可追溯性核心：K_i 完整恢复）
        dec_k_i_bytes = ubyte_ptr_to_bytes(dec_k_i, dec_len.value)
        self.assertEqual(dec_k_i_bytes, k_i, "部分密钥 K_i 解密不一致，可追溯性验证失败")

    def test_tma_key_exchange_with_lac_kem(self):
        """测试车联网 TMA 场景下基于 LAC KEM 的密钥协商"""
        # 1. 生成车辆与 TMA 服务端的密钥对
        pk_vehicle = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_vehicle = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_kem_keypair(pk_vehicle, sk_vehicle)

        pk_tma = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_tma = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_kem_keypair(pk_tma, sk_tma)

        # 2. 车辆向 TMA 发起密钥协商（封装）
        ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        ss_vehicle = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret = lib.crypto_kem_enc(ct, ss_vehicle, pk_tma)
        self.assertEqual(ret, 0, "车辆 KEM 封装失败")

        # 3. TMA 解封装，生成共享密钥
        ss_tma = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret = lib.crypto_kem_dec(ss_tma, ct, sk_tma)
        self.assertEqual(ret, 0, "TMA KEM 解封装失败")

        # 4. 验证共享密钥一致（TMA 与车辆安全通信基础）
        self.assertEqual(bytes(ss_vehicle), bytes(ss_tma), "TMA 与车辆共享密钥不一致")

if __name__ == '__main__':
    unittest.main()
