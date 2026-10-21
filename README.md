# 真实 LAC 调用说明

当前目录只保留真实 `LAC` 相关内容，用于：

1. 编译 `LAC/Additional_Implementation` 的桥接动态库 `lac_bridge.dll`
2. 通过 Python `ctypes` 调用真实 `LAC` 的 `PKE` 和 `KEM`
3. 运行真实 `LAC` 的加密、解密、封装、解封装测试

## 保留文件

- `lac_real.py`
  Python 对真实 `lac_bridge.dll` 的调用封装
- `test_lac_real.py`
  真实 `LAC` 的单元测试
- `lac_traceability.py`
  正式的注册、举报、TMA 追踪模块
- `test_lac_traceability.py`
  针对注册、伪名校验、追踪的测试
- `run_lac_traceability_check.py`
  按步骤打印注册与追踪结果
- `lac_signcrypt.py`
  伪名验证通过后进入签密流程的正式模块
- `test_lac_signcrypt.py`
  针对签密、解签密、重放拦截、伪造拒绝的测试
- `run_lac_signcrypt_check.py`
  按步骤打印伪名验证、签密、解签密结果
- `run_lac_full_protocol_check.py`
  一次性打印注册、车辆互验伪名、签密、TMA 追踪完整流程
- `test_lac_full_flow.py`
  完整链路集成测试
- `build_lac_bridge.ps1`
  在本机 `MSYS2 + gcc + OpenSSL` 环境下重建 `lac_bridge.dll`
- `LAC/Additional_Implementation/lac_bridge.c`
  为 Python 暴露 `PKE` 和 `KEM` 接口的桥接层

## 重新构建桥接库

先进入项目目录：

```powershell
cd "e:\最靠谱程序员群单子\调用lac库"
```

执行构建脚本：

```powershell
powershell -ExecutionPolicy Bypass -File ".\build_lac_bridge.ps1"
```

构建脚本会：

1. 把 `LAC/Additional_Implementation` 复制到 `C:\lac_build\Additional_Implementation`
2. 用 `MSYS2 UCRT64 gcc` 编译 `lac_bridge.dll`
3. 把 `lac_bridge.dll` 和 `libcrypto-3-x64.dll` 复制回项目目录

## 运行真实 LAC 测试

运行：

```powershell
python -m unittest test_lac_real
python -m unittest test_lac_traceability
```

签密模块使用独立的本地 Python 3.12 便携环境，运行：

```powershell
.\.py312\python.exe -m unittest test_lac_signcrypt
.\.py312\python.exe -m unittest test_lac_full_flow
```

当前测试覆盖：

1. `PKE` 加密/解密往返
2. `K_i` 明文下发往返
3. 错误私钥不能恢复原始 `K_i`
4. `KEM` 封装/解封装往返
5. 错误 `KEM` 私钥不能恢复原始共享密钥

追踪测试覆盖：

1. 注册阶段使用真实 `LAC` 下发 `K_i`
2. 合法伪名可被公开校验并追踪
3. 伪造伪名但仍携带注册绑定参数时可被追踪
4. 未注册外部伪造材料不可被追踪

## 运行一步一步的追踪输出

```powershell
python ".\run_lac_traceability_check.py"
```

这个脚本会输出：

1. 注册阶段的临时公钥长度、加密后 `K_i` 长度、`K_i` 校验结果
2. 合法伪名是否有效、是否能追踪到真实身份
3. 伪造伪名是否无效、是否仍能追踪到注册身份
4. 未注册外部攻击者是否无法追踪

## 运行一步一步的签密输出

```powershell
.\.py312\python.exe ".\run_lac_signcrypt_check.py"
```

这个脚本会输出：

1. 注册阶段真实 `LAC` 下发 `K_i` 是否成功
2. 两辆车本地伪名验证是否通过
3. 验证通过后是否完成 `LAC KEM` + `SPHINCS+` + `AESGCM` 签密
4. 接收方是否成功解签密并验证 `SPHINCS+`
5. 伪造伪名是否会在签密前被拒绝

## 运行完整流程

```powershell
.\.py312\python.exe ".\run_lac_full_protocol_check.py"
```

这个脚本会一次性输出：

1. 三辆车注册时真实 `LAC` 下发 `K_i` 是否成功
2. 两辆车是否成功互验伪名
3. 验证通过后是否完成签密
4. 接收方是否成功解签密并验证 `SPHINCS+`
5. 伪造伪名是否被车辆拒绝
6. 伪造伪名是否可被 `TMA` 追踪
7. 未注册外部攻击者是否无法被追踪

## 当前真实接口

桥接层当前导出了这些真实 `LAC` 接口：

- `lac_pke_keypair`
- `lac_pke_encrypt`
- `lac_pke_decrypt`
- `lac_wrap_partial_key`
- `lac_unwrap_partial_key`
- `lac_kem_keypair`
- `lac_kem_encapsulate`
- `lac_kem_decapsulate`
