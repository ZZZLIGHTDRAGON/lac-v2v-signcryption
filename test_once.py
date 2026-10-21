from lac_car_kgc import CarA, KGC, TMA, verify_and_decrypt, pseudonym_verify

print("="*60)
print("  单次完整流程测试")
print("="*60)

# 1. 系统初始化
print("\n1. 系统初始化...")
kgc = KGC()
tma = TMA()
Y_T = tma.trace_public_YT
print("✅ KGC和TMA初始化完成")

# 2. 生成两辆车
print("\n2. 生成两辆车并注册...")
car1 = CarA()
car2 = CarA()
print(f"✅ 车1真实ID: {car1.real_id[:8]}...")
print(f"✅ 车2真实ID: {car2.real_id[:8]}...")

# 3. 车辆注册和密钥分发
car1.lac_generate_temp_keypair()
raw1 = kgc.lac_generate_partial_key(car1.temp_pk)
enc1 = car1.lac_encrypt_K(raw1, car1.temp_pk)
car1.lac_decrypt_K(enc1)
W1, C1 = tma.car_register(car1.real_id, car1.w_i)
car1.car_generate_long_term_state_and_pool(raw1, W1, C1)

car2.lac_generate_temp_keypair()
raw2 = kgc.lac_generate_partial_key(car2.temp_pk)
enc2 = car2.lac_encrypt_K(raw2, car2.temp_pk)
car2.lac_decrypt_K(enc2)
W2, C2 = tma.car_register(car2.real_id, car2.w_i)
car2.car_generate_long_term_state_and_pool(raw2, W2, C2)
print("✅ 两辆车注册和密钥分发完成")

# 4. 提取伪名
print("\n3. 从状态池提取伪名...")
pid1 = car1.car_extract_pseudonym_from_pool()
pid2 = car2.car_extract_pseudonym_from_pool()
print(f"✅ 车1伪名: {pid1[0].hex()[:16]}...")
print(f"✅ 车2伪名: {pid2[0].hex()[:16]}...")

# 5. 生成会话密钥
print("\n4. 生成会话密钥与签名...")
skp1, omg1 = car1.car_generate_session_key_and_sign(pid1)
skp2, omg2 = car2.car_generate_session_key_and_sign(pid2)
print("✅ 会话密钥生成完成")

# 6. 伪名验证
print("\n5. 伪名验证...")
assert pseudonym_verify(omg1, Y_T)
assert pseudonym_verify(omg2, Y_T)
print("✅ 伪名验证通过")

# 7. 签密和解密
print("\n6. 签密和解密测试...")
test_msg = b"Hello, this is a test V2V message!"
pkg = car1.car_signcrypt(test_msg, omg2, Y_T)
print("✅ 签密完成")

dec_msg = verify_and_decrypt(pkg, car2.kem_sk, omg2, Y_T)
assert dec_msg == test_msg
print(f"✅ 解密成功，消息: {dec_msg.decode()}")

# 8. 伪名追踪
print("\n7. 伪名追踪测试...")
traced_id = tma.tma_trace_malicious_pseudonym(pid1)
assert traced_id == car1.real_id
print(f"✅ 追踪成功，真实ID: {traced_id[:8]}...")

print("\n" + "="*60)
print("🎉 恭喜！一次完整流程全部成功！")
print("="*60)
