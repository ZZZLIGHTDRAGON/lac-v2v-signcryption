import unittest
from lac_car_kgc import CarA, KGC, TMA, verify_and_decrypt, pseudonym_verify

class TestLACFullScheme(unittest.TestCase):
    def test_方案9大算法全流程(self):
        """端到端完整测试：覆盖你方案的全部9个算法"""
        print("="*80)
        print("开始执行 方案全部9大算法 端到端全流程测试")
        print("="*80)

        # ===================== 算法1：系统生成算法（Setup） =====================
        print("\n【算法1：系统生成算法 Setup】")
        kgc = KGC()
        tma = TMA()
        # 系统公共参数核心要素
        Y_T = tma.trace_public_YT
        params = {
            "lambda": 128,
            "PK_LAC": b"PK_LAC_STANDARD",
            "H_SM3": "国密SM3哈希",
            "P_pub": kgc.master_public_Ppub,
            "Y_T": Y_T
        }
        print("✅ 算法1完成：系统公共参数生成成功")

        # ===================== 初始化两车：车A（发送方）、车B（接收方） =====================
        car_A = CarA()  # 发送方车辆
        car_B = CarA()  # 接收方车辆
        print(f"\n车A真实身份ID：{car_A.real_id}")
        print(f"车B真实身份ID：{car_B.real_id}")

        # ===================== 算法2：部分密钥生成算法（Pkey-gen） 两车分别执行 =====================
        print("\n【算法2：部分密钥生成算法 Pkey-gen】")
        # 车A流程
        car_A.lac_generate_temp_keypair()
        W_A, C_A = tma.car_register(car_A.real_id, car_A.temp_pk)
        encrypted_K_A, raw_K_A = kgc.lac_encrypt_K(car_A.temp_pk)
        car_A.lac_decrypt_K(encrypted_K_A)

        # 车B流程
        car_B.lac_generate_temp_keypair()
        W_B, C_B = tma.car_register(car_B.real_id, car_B.temp_pk)
        encrypted_K_B, raw_K_B = kgc.lac_encrypt_K(car_B.temp_pk)
        car_B.lac_decrypt_K(encrypted_K_B)
        print("✅ 算法2完成：两车部分密钥生成与分发成功")

        # ===================== 算法3：用户秘密值生成与长期状态算法（Fkey-gen） =====================
        print("\n【算法3：长期状态生成算法 Fkey-gen】")
        car_A.car_generate_long_term_state(car_A.part_key_K, W_A, C_A)
        car_B.car_generate_long_term_state(car_B.part_key_K, W_B, C_B)
        print("✅ 算法3完成：两车长期私有状态生成成功")

        # ===================== 算法4：伪名生成算法（Pseudonym-Gen） =====================
        print("\n【算法4：伪名生成算法 Pseudonym-Gen】")
        PID_A = car_A.car_generate_pseudonym()
        PID_B = car_B.car_generate_pseudonym()
        print(f"车A伪名PID_A1：{PID_A[0].hex()[:32]}...")
        print(f"车A伪名PID_A2：{PID_A[1].hex()[:32]}...")
        print(f"车B伪名PID_B1：{PID_B[0].hex()[:32]}...")
        print(f"车B伪名PID_B2：{PID_B[1].hex()[:32]}...")
        print("✅ 算法4完成：两车伪名生成成功")

        # ===================== 算法5：会话密钥与绑定签名算法（Psmkey-gen） =====================
        print("\n【算法5：会话密钥与绑定签名算法 Psmkey-gen】")
        SKP_A, omega_A = car_A.car_generate_session_key_and_sign(PID_A)
        SKP_B, omega_B = car_B.car_generate_session_key_and_sign(PID_B)
        print("✅ 算法5完成：两会话密钥与绑定签名生成成功")

        # ===================== 算法6：伪名验证算法（Psm-veri） =====================
        print("\n【算法6：伪名验证算法 Psm-veri】")
        # 车B验证车A的公开材料
        verify_result = pseudonym_verify(omega_A, params["Y_T"])
        self.assertTrue(verify_result, "车A伪名验证失败")
        # 车A验证车B的公开材料
        verify_result = pseudonym_verify(omega_B, params["Y_T"])
        self.assertTrue(verify_result, "车B伪名验证失败")

        # ===================== 算法8：签密算法（Sign） 车A给车B发消息 =====================
        print("\n【算法8：签密算法 Sign】")
        # 修正：中文消息先写字符串再encode，解决字节串中文语法错误
        test_message = "V2V message: 前方500米有事故，请注意减速".encode('utf-8')
        signcrypt_package = car_A.car_signcrypt(test_message, omega_B, params["Y_T"])
        print(f"待发送消息：{test_message.decode('utf-8')}")
        print("✅ 算法8完成：消息签密成功")

        # ===================== 算法9：验证与解密算法（Verify） 车B接收并解密消息 =====================
        print("\n【算法9：验证与解密算法 Verify】")
        decrypted_message = verify_and_decrypt(
            signcrypt_package,
            car_B.kem_sk,
            omega_B,
            params["Y_T"]
        )
        self.assertEqual(decrypted_message, test_message, "消息解密验证失败")
        print(f"解密后消息：{decrypted_message.decode('utf-8')}")
        print("✅ 算法9完成：消息验证与解密成功")

        # ===================== 算法7：伪名追踪算法（Tracing） TMA追踪恶意伪名 =====================
        print("\n【算法7：伪名追踪算法 Tracing】")
        # 模拟恶意伪名（车A的伪名）
        malicious_PID = PID_A
        traced_real_id = tma.tma_trace_malicious_pseudonym(malicious_PID)
        self.assertEqual(traced_real_id, car_A.real_id, "伪名追踪失败")
        print("✅ 算法7完成：恶意伪名追踪成功")

        # ===================== 全流程完成 =====================
        print("\n" + "="*80)
        print("🎉 恭喜！你的方案全部9大算法 端到端全流程测试全部通过！")
        print("="*80)

if __name__ == '__main__':
    unittest.main(verbosity=2)


