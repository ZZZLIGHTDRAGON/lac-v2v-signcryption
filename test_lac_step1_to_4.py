import unittest
from lac_car_kgc import CarA, KGC

class TestLACSchemeStep1To4(unittest.TestCase):
    def test_方案步骤1到4全流程(self):
        """端到端完整测试，完全匹配你的方案4个核心步骤"""
        print("="*60)
        print("开始执行 车A真实名+伪名前置流程 全流程测试")
        print("="*60)

        # 步骤1：车A生成自己的真实身份
        car_A = CarA()
        kgc = KGC()
        print(f"步骤1完成：车A真实身份ID = {car_A.real_id}")

        # 步骤2：车A生成LAC临时公钥与私钥
        car_A.lac_generate_temp_keypair()

        # 步骤3：KGC用临时公钥加密部分密钥K并下发
        encrypted_K, raw_K = kgc.lac_encrypt_K(car_A.temp_pk)

        # 步骤4：车A用临时私钥解密K
        decrypted_K = car_A.lac_decrypt_K(encrypted_K)

        # 核心验证：解密后的K和原始K完全一致
        self.assertEqual(decrypted_K, raw_K, "解密验证失败：K值不匹配")
        print("="*60)
        print("🎉 全流程测试全部通过！完全匹配你的方案要求")
        print(f"原始K值：{raw_K.hex()}")
        print(f"解密K值：{decrypted_K.hex()}")
        print("="*60)

if __name__ == '__main__':
    unittest.main(verbosity=2)
    
    import unittest
from lac_car_kgc import CarA, KGC, TMA

class TestLACPseudonymGen(unittest.TestCase):
    def test_方案全流程_注册到伪名生成(self):
        """测试方案完整流程：真实名生成→临时密钥→KGC加密解密→TMA注册→长期状态→伪名生成"""
        print("="*60)
        print("开始执行 方案完整流程（注册→伪名生成）测试")
        print("="*60)

        # 1. 初始化三方主体（匹配方案算法1 系统生成）
        car_A = CarA()
        kgc = KGC()
        tma = TMA()
        print(f"1. 系统初始化完成，车A真实身份ID = {car_A.real_id}")

        # 2. 车A生成LAC临时密钥对（方案算法2步骤1）
        car_temp_pk = car_A.lac_generate_temp_keypair()

        # 3. TMA处理注册，生成Wi、Ci（方案算法2步骤2）
        W_i, C_i = tma.car_register(car_A.real_id, car_temp_pk)

        # 4. KGC生成并加密部分密钥K（方案算法2步骤4）
        encrypted_K, raw_K = kgc.lac_encrypt_K(car_temp_pk)

        # 5. 车A解密得到部分密钥K（方案算法2步骤5）
        decrypted_K = car_A.lac_decrypt_K(encrypted_K)
        self.assertEqual(decrypted_K, raw_K, "K值解密验证失败")

        # 6. 车A生成长期私有状态SKi（方案算法3）
        car_A.car_generate_long_term_state(decrypted_K, W_i, C_i)

        # 7. 车A生成伪名PIDi（方案算法4）
        PID_i = car_A.car_generate_pseudonym()
        print(f"7. 生成的双组件伪名：")
        print(f"   PID_i1 = {PID_i[0].hex()}")
        print(f"   PID_i2 = {PID_i[1].hex()}")
        print(f"   {car_A.pseudonym_verify_relation}")

        print("="*60)
        print("🎉 方案完整流程（注册→伪名生成）全部测试通过！")
        print("="*60)

if __name__ == '__main__':
    unittest.main(verbosity=2)
