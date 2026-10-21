import time
import statistics
from lac_car_kgc import CarA, KGC, TMA, verify_and_decrypt, pseudonym_verify

def print_separator(title=""):
    print("\n" + "="*80)
    if title:
        print(f"  {title}")
        print("="*80)

def main():
    # 测试配置
    TEST_ROUNDS = 100  # 测试100次取平均
    print_separator("基于LAC国密的车联网伪名方案 - 100次循环性能测试")
    print(f"测试时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"测试平台：Linux (Ubuntu)")
    print(f"测试轮数：{TEST_ROUNDS} 次")
    print("="*80)

    # ===================== 【一次性初始化】放在循环外 =====================
    print_separator("【初始化】系统生成（仅执行1次）")
    kgc = KGC()
    tma = TMA()
    Y_T = tma.trace_public_YT
    print("✅ 系统初始化完成")

    # 初始化两车（仅执行1次）
    car_A = CarA()
    car_B = CarA()
    print(f"\n车A真实身份ID：{car_A.real_id}")
    print(f"车B真实身份ID：{car_B.real_id}")

    # ===================== 【性能测试数据存储】 =====================
    timings = {
        "算法2：部分密钥生成": [],
        "算法3：长期状态生成": [],
        "算法4：伪名生成": [],
        "算法5：会话密钥与绑定签名": [],
        "算法6：伪名验证": [],
        "算法7：伪名追踪": [],
        "算法8：签密": [],
        "算法9：验证与解密": []
    }

    # ===================== 【100次循环测试】 =====================
    print_separator(f"开始 {TEST_ROUNDS} 次循环测试...")
    for i in range(TEST_ROUNDS):
        if (i + 1) % 20 == 0:
            print(f"  正在进行第 {i+1}/{TEST_ROUNDS} 次测试...")

        # --- 算法2：部分密钥生成 ---
        start = time.time()
        car_A.lac_generate_temp_keypair()
        W_A, C_A = tma.car_register(car_A.real_id, car_A.temp_pk)
        encrypted_K_A, raw_K_A = kgc.lac_encrypt_K(car_A.temp_pk)
        car_A.lac_decrypt_K(encrypted_K_A)
        
        car_B.lac_generate_temp_keypair()
        W_B, C_B = tma.car_register(car_B.real_id, car_B.temp_pk)
        encrypted_K_B, raw_K_B = kgc.lac_encrypt_K(car_B.temp_pk)
        car_B.lac_decrypt_K(encrypted_K_B)
        end = time.time()
        timings["算法2：部分密钥生成"].append((end - start) * 1000)

        # --- 算法3：长期状态生成 ---
        start = time.time()
        car_A.car_generate_long_term_state(car_A.part_key_K, W_A, C_A)
        car_B.car_generate_long_term_state(car_B.part_key_K, W_B, C_B)
        end = time.time()
        timings["算法3：长期状态生成"].append((end - start) * 1000)

        # --- 算法4：伪名生成 ---
        start = time.time()
        PID_A = car_A.car_generate_pseudonym()
        PID_B = car_B.car_generate_pseudonym()
        end = time.time()
        timings["算法4：伪名生成"].append((end - start) * 1000)

        # --- 算法5：会话密钥与绑定签名 ---
        start = time.time()
        SKP_A, omega_A = car_A.car_generate_session_key_and_sign(PID_A)
        SKP_B, omega_B = car_B.car_generate_session_key_and_sign(PID_B)
        end = time.time()
        timings["算法5：会话密钥与绑定签名"].append((end - start) * 1000)

        # --- 算法6：伪名验证 ---
        start = time.time()
        verify_A = pseudonym_verify(omega_A, Y_T)
        verify_B = pseudonym_verify(omega_B, Y_T)
        end = time.time()
        timings["算法6：伪名验证"].append((end - start) * 1000)
        assert verify_A and verify_B, "伪名验证失败"

        # --- 算法8：签密 ---
        test_message = "V2V message: 前方500米有事故，请注意减速".encode('utf-8')
        start = time.time()
        signcrypt_package = car_A.car_signcrypt(test_message, omega_B, Y_T)
        end = time.time()
        timings["算法8：签密"].append((end - start) * 1000)

        # --- 算法9：验证与解密 ---
        start = time.time()
        decrypted_message = verify_and_decrypt(
            signcrypt_package,
            car_B.kem_sk,
            omega_B,
            Y_T
        )
        end = time.time()
        timings["算法9：验证与解密"].append((end - start) * 1000)
        assert decrypted_message == test_message, "消息解密验证失败"

        # --- 算法7：伪名追踪 ---
        malicious_PID = PID_A
        start = time.time()
        traced_real_id = tma.tma_trace_malicious_pseudonym(malicious_PID)
        end = time.time()
        timings["算法7：伪名追踪"].append((end - start) * 1000)
        assert traced_real_id == car_A.real_id, "伪名追踪失败"

    print(f"\n✅ {TEST_ROUNDS} 次循环测试全部完成！")

    # ===================== 【输出专业性能测试结果表格】 =====================
    print_separator(f"性能测试结果汇总（{TEST_ROUNDS}次平均，单位：毫秒 ms）")
    print(f"{'算法名称':<30} | {'平均耗时':<12} | {'最小耗时':<12} | {'最大耗时':<12}")
    print("-" * 80)
    
    total_avg = 0.0
    for algo_name, time_list in timings.items():
        avg_time = statistics.mean(time_list)
        min_time = min(time_list)
        max_time = max(time_list)
        total_avg += avg_time
        print(f"{algo_name:<30} | {avg_time:<12.2f} | {min_time:<12.2f} | {max_time:<12.2f}")
    
    print("-" * 80)
    print(f"{'全流程平均总耗时':<30} | {total_avg:<12.2f} | {'-':<12} | {'-':<12}")
    print("="*80)
    print("🎉 恭喜！100次循环性能测试全部完成！")
    print("💡 提示：以上数据可直接用于论文实验结果分析")
    print("="*80)

if __name__ == '__main__':
    main()

