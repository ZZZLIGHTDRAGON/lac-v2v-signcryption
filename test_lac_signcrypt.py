import unittest
import ctypes
import os
from lac_real import (
    lib,
    bytes_to_ubyte_ptr,
    ubyte_ptr_to_bytes,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_BYTES
)

class TestLACSigncrypt(unittest.TestCase):
    """
    基于 LAC 格密码的车联网安全通信测试（适配 LAC 官方 PKE/KEM 接口）
    功能：1. 基于 KEM 的安全密钥协商（车联网会话安全）；2. 基于 PKE 的消息加密传输（替代签密，满足车联网安全需求）
    """

    def test_lac_kem_signcrypt_key_exchange(self):
        """测试基于 KEM 的密钥协商（车联网安全会话，完全匹配 LAC 官方接口）"""
        # 1. 生成车辆与 TMA/RSU 密钥对
        pk_vehicle = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_vehicle = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        ret_kp1 = lib.crypto_kem_keypair(pk_vehicle, sk_vehicle)
        self.assertEqual(ret_kp1, 0, "车辆 KEM 密钥生成失败")

        pk_tma = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_tma = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        ret_kp2 = lib.crypto_kem_keypair(pk_tma, sk_tma)
        self.assertEqual(ret_kp2, 0, "TMA KEM 密钥生成失败")

        # 2. 车辆发起 KEM 封装（生成共享密钥）
        ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        ss_send = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret_enc = lib.crypto_kem_enc(ct, ss_send, pk_tma)
        self.assertEqual(ret_enc, 0, "KEM 封装失败")

        # 3. TMA 解封装（恢复共享密钥）
        ss_recv = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret_dec = lib.crypto_kem_dec(ss_recv, ct, sk_tma)
        self.assertEqual(ret_dec, 0, "KEM 解封装失败")

        # 4. 验证共享密钥一致（车联网安全会话核心）
        self.assertEqual(bytes(ss_send), bytes(ss_recv), "KEM 共享密钥不一致，密钥协商失败")

    def test_lac_pke_message_encryption(self):
        """测试基于 LAC PKE 的车联网消息加密传输（替代签密，满足消息机密性）"""
        # 1. 生成通信双方密钥对
        pk_sender = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_sender = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_encrypt_keypair(pk_sender, sk_sender)

        pk_receiver = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk_receiver = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_encrypt_keypair(pk_receiver, sk_receiver)

        # 2. 车联网短消息（控制长度在 LAC-CPA 限制内，避免加密失败）
        message = b"Vehicle_123 | Speed_60"
        msg_len = len(message)
        self.assertLessEqual(msg_len, CRYPTO_CIPHERTEXTBYTES - 32, "消息长度超出 LAC PKE 限制")
        msg_ptr = bytes_to_ubyte_ptr(message)

        # 3. 发送方加密（LAC PKE 官方接口）
        ciphertext = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        ct_len = ctypes.c_ulonglong(0)
        ret_enc = lib.crypto_encrypt(
            ciphertext,
            ctypes.byref(ct_len),
            msg_ptr,
            msg_len,
            pk_receiver
        )
        self.assertEqual(ret_enc, 0, "PKE 加密失败")

        # 4. 接收方解密（LAC PKE 官方接口）
        decrypted_msg = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        dec_len = ctypes.c_ulonglong(0)
        ret_dec = lib.crypto_encrypt_open(
            decrypted_msg,
            ctypes.byref(dec_len),
            ciphertext,
            ct_len.value,
            sk_receiver
        )
        self.assertEqual(ret_dec, 0, "PKE 解密失败")

        # 5. 验证消息一致性
        final_msg = ubyte_ptr_to_bytes(decrypted_msg, dec_len.value)
        self.assertEqual(final_msg, message, "PKE 解密消息不一致，消息加密失败")

if __name__ == '__main__':
    unittest.main()
