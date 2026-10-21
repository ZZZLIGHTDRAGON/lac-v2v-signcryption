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

class TestLACOfficial(unittest.TestCase):
    def test_pke_encrypt_decrypt(self):
        """测试 PKE 加密/解密（严格匹配 LAC 官方接口）"""
        # 1. 生成密钥对
        pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        ret = lib.crypto_encrypt_keypair(pk, sk)
        self.assertEqual(ret, 0, "密钥生成失败")

        # 2. 准备明文
        msg = b"test1234"
        mlen = len(msg)
        m_ptr = bytes_to_ubyte_ptr(msg)

        # 3. 加密（按官方参数顺序，传递长度指针）
        ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        clen = ctypes.c_ulonglong(0)  # 输出密文长度
        ret = lib.crypto_encrypt(ct, ctypes.byref(clen), m_ptr, mlen, pk)
        self.assertEqual(ret, 0, "加密失败")

        # 4. 解密（按官方参数顺序，传递长度指针）
        dec = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        dec_len = ctypes.c_ulonglong(0)  # 输出明文长度
        ret = lib.crypto_encrypt_open(dec, ctypes.byref(dec_len), ct, clen.value, sk)
        self.assertEqual(ret, 0, "解密失败")

        # 5. 验证：只取解密出的有效长度字节
        dec_bytes = ubyte_ptr_to_bytes(dec, dec_len.value)
        self.assertEqual(dec_bytes, msg, "解密结果与明文不一致")

    def test_kem_encaps_decaps(self):
        """测试 KEM 封装/解封装（严格匹配 LAC 官方接口）"""
        # 1. 生成密钥对
        pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        ret = lib.crypto_kem_keypair(pk, sk)
        self.assertEqual(ret, 0, "KEM 密钥生成失败")

        # 2. 封装
        ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        ss1 = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret = lib.crypto_kem_enc(ct, ss1, pk)
        self.assertEqual(ret, 0, "KEM 封装失败")

        # 3. 解封装
        ss2 = (ctypes.c_ubyte * CRYPTO_BYTES)()
        ret = lib.crypto_kem_dec(ss2, ct, sk)
        self.assertEqual(ret, 0, "KEM 解封装失败")

        # 4. 验证共享密钥一致
        ss1_bytes = ubyte_ptr_to_bytes(ss1, CRYPTO_BYTES)
        ss2_bytes = ubyte_ptr_to_bytes(ss2, CRYPTO_BYTES)
        self.assertEqual(ss1_bytes, ss2_bytes, "KEM 共享密钥不一致")

if __name__ == '__main__':
    unittest.main()
