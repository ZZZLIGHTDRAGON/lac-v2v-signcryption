V2V 匿名通信演示（Linux Ubuntu，普通 CPython 3.12，VS Code）
1. 在虚拟机解压，在 VS Code 打开包含 demo.py 的 V2V_VSCode 文件夹。
2. 在该目录的集成终端执行：
   sudo apt install build-essential libssl-dev python3-venv
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   sh build_lac.sh
   .venv/bin/python demo.py
3. 安装 VS Code Python 和 Python Debugger 扩展，执行 Python: Select Interpreter，
   选择本目录的 .venv/bin/python，按 F5 运行“演示 V2V 会话”。
无需 Sage、PySPX Python 扩展或 Windows DLL。源码已随包附带，构建脚本在
临时目录编译，请勿将原项目的 .so 改名来代替这一步。
源码：附件 LAC/Reference_Implementation 及 PySPX-0.5.0.tar.gz 内的
SPHINCS+ ref。在临时 LAC 源码中用 OpenSSL RAND_bytes 替代 KAT 随机流；
签名编译 shake-128s 参数与 thash_shake_simple.c。LAC KEM 密文为 1024 字节。
SM4-GCM 使用共享密钥前 16 字节。SM3 需要 Python 的 OpenSSL 后端支持。
实现边界：同进程模拟可信注册信道及历史接收时间；状态存于内存。
绑定采用 k_bind=1 的小维度演示参数，环乘法和陪集更新使用 Python 整数。
陷门采样使用 NumPy QR 浮点投影、有限窗口一维离散高斯及范数拒绝；
不是 Sage 采样器的逐位等价替换，不是已审计的安全实例。不要用于部署，
也不要用演示输出代替原论文实验数据。demo.py 在协议成功时打印结果，
不会展示私钥或共享密钥；不兼容旧的 CarA 单元测试。
