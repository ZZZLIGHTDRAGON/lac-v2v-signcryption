import ctypes
import os

# ====================== 加载 LAC 官方动态库 ======================
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(PROJECT_ROOT, "liblac.so")
lib = ctypes.CDLL(LIB_PATH)

# ====================== LAC 官方标准参数 ======================
CRYPTO_PUBLICKEYBYTES = 896
CRYPTO_SECRETKEYBYTES = 1792
CRYPTO_CIPHERTEXTBYTES = 1024
CRYPTO_BYTES = 32

# ====================== 1. PKE 接口（严格匹配官方签名）======================
# crypto_encrypt_keypair: 生成密钥对
lib.crypto_encrypt_keypair.restype = ctypes.c_int
lib.crypto_encrypt_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # pk: 公钥
    ctypes.POINTER(ctypes.c_ubyte)   # sk: 私钥
]

# crypto_encrypt: 加密（官方真实参数顺序）
lib.crypto_encrypt.restype = ctypes.c_int
lib.crypto_encrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),        # c: 输出密文
    ctypes.POINTER(ctypes.c_ulonglong),    # clen: 输出密文长度指针
    ctypes.POINTER(ctypes.c_ubyte),        # m: 输入明文
    ctypes.c_ulonglong,                    # mlen: 明文长度
    ctypes.POINTER(ctypes.c_ubyte)         # pk: 公钥
]

# crypto_encrypt_open: 解密（官方真实参数顺序）
lib.crypto_encrypt_open.restype = ctypes.c_int
lib.crypto_encrypt_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),        # m: 输出明文
    ctypes.POINTER(ctypes.c_ulonglong),    # mlen: 输出明文长度指针
    ctypes.POINTER(ctypes.c_ubyte),        # c: 输入密文
    ctypes.c_ulonglong,                    # clen: 密文长度
    ctypes.POINTER(ctypes.c_ubyte)         # sk: 私钥
]

# ====================== 2. KEM 接口（严格匹配官方签名）======================
# crypto_kem_keypair: 生成密钥对
lib.crypto_kem_keypair.restype = ctypes.c_int
lib.crypto_kem_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # pk: 公钥
    ctypes.POINTER(ctypes.c_ubyte)   # sk: 私钥
]

# crypto_kem_enc: 封装
lib.crypto_kem_enc.restype = ctypes.c_int
lib.crypto_kem_enc.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # c: 输出密文
    ctypes.POINTER(ctypes.c_ubyte),  # ss: 输出共享密钥
    ctypes.POINTER(ctypes.c_ubyte)   # pk: 公钥
]

# crypto_kem_dec: 解封装
lib.crypto_kem_dec.restype = ctypes.c_int
lib.crypto_kem_dec.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # ss: 输出共享密钥
    ctypes.POINTER(ctypes.c_ubyte),  # c: 输入密文
    ctypes.POINTER(ctypes.c_ubyte)   # sk: 私钥
]

# ====================== 工具函数 ======================
def bytes_to_ubyte_ptr(b: bytes):
    """将 Python bytes 转换为 C 风格 unsigned char 指针"""
    arr = (ctypes.c_ubyte * len(b)).from_buffer_copy(b)
    return arr

def ubyte_ptr_to_bytes(ptr, length: int) -> bytes:
    """将 C 风格 unsigned char 指针转换为 Python bytes"""
    return bytes(ptr[:length])
