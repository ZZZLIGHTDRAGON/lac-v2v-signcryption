
import ctypes
import uuid
import os
import hashlib
import random
from lac_real import (
    lib,
    bytes_to_ubyte_ptr,
    ubyte_ptr_to_bytes,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_BYTES
)
from gmssl import sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import pyspx.shake_128f as sphincs
import time

LAC_VECTOR_SIZE = CRYPTO_BYTES
LAC_MATRIX_SIZE = LAC_VECTOR_SIZE * LAC_VECTOR_SIZE

ETA = 3
OMEGA = 12
BETA = 128
REJECT_BOUND = BETA

def gen_matrix(seed):
    m = b''
    cnt = 0
    while len(m) < LAC_MATRIX_SIZE:
        m += hashlib.sha256(seed + cnt.to_bytes(4, 'little')).digest()
        cnt += 1
    return m[:LAC_MATRIX_SIZE]

MATRIX_A0 = gen_matrix(b'A0_TRAPDOOR_MASTER')
TRAPDOOR_T0 = gen_matrix(b'TRAPDOOR_SHORT_BASIS')
MATRIX_A1 = gen_matrix(b'A1_PUBLIC_NO_TRAPDOOR')

H = lambda x: bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x)))
H1 = lambda x: bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x)))
H2 = lambda x: bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x)))[:4]
H_SESS = lambda x: bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x)))
H_SM3 = lambda x: bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x)))

def lac_preimage_sample(A, trap, target):
    return trap[:LAC_VECTOR_SIZE]

def mat_vec_mul(A, x):
    res = bytearray(LAC_VECTOR_SIZE)
    for i in range(LAC_VECTOR_SIZE):
        row = A[i*LAC_VECTOR_SIZE : (i+1)*LAC_VECTOR_SIZE]
        s = sum(row[j] * x[j] for j in range(LAC_VECTOR_SIZE)) % 256
        res[i] = s
    return bytes(res)

def vec_add(a, b):
    return bytes((a[i] + b[i]) % 256 for i in range(len(a)))

def vec_sub(a, b):
    return bytes((a[i] - b[i] + 256) % 256 for i in range(len(a)))

def scalar_mul(s, v):
    return bytes((s * x) % 256 for x in v)

def vec_inf_norm(v):
    return max(abs(x - 128) for x in v)

def gaussian_sample():
    return bytes(128 + random.randint(-ETA, ETA) for _ in range(LAC_VECTOR_SIZE))

class KGC:
    def __init__(self):
        self.A0 = MATRIX_A0
        self.T0 = TRAPDOOR_T0
        self.A1 = MATRIX_A1

    def generate_partial_key(self, pk_car):
        t = H1(pk_car)[:LAC_VECTOR_SIZE]
        Ki = lac_preimage_sample(self.A0, self.T0, t)
        ct = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        l = ctypes.c_ulonglong()
        lib.crypto_encrypt(ct, ctypes.byref(l), bytes_to_ubyte_ptr(Ki), len(Ki), bytes_to_ubyte_ptr(pk_car))
        return ubyte_ptr_to_bytes(ct, l.value), Ki

class TMA:
    def __init__(self):
        self.trace_public_YT = gen_matrix(b'TRACE_YT_PUBLIC')
        self.EIT_registry = {}

    def car_register(self, rid, wi, Ki, Xi):
        Wi = mat_vec_mul(MATRIX_A0, Ki)
        pad = wi.ljust(LAC_VECTOR_SIZE, b'\x00')
        Ci = mat_vec_mul(self.trace_public_YT, pad)
        pid_hash = H(wi).hex()
        self.EIT_registry[pid_hash] = {
            'real_id': rid,
            'w_i': wi,
            'W_i': Wi,
            'C_i': Ci,
            'X_orig': Xi,
            'status': 'unused',
            'sid': None,
            'peer_pid': None,
            'exp_time': 0
        }
        return Wi, Ci

    def activate(self, omega_A, omega_B):
        pid_A = omega_A['PID_i'][0]
        pid_B = omega_B['PID_i'][0]
        X_A = omega_A['X_i']
        X_B = omega_B['X_i']
        key_A = H(pid_A[5+16:5+16+16]).hex()
        key_B = H(pid_B[5+16:5+16+16]).hex()
        if key_A not in self.EIT_registry or key_B not in self.EIT_registry:
            return False, 'PID not registered'
        entry_A = self.EIT_registry[key_A]
        entry_B = self.EIT_registry[key_B]
        if entry_A['X_orig'] != X_A or entry_B['X_orig'] != X_B:
            return False, 'X mismatch - possible framing attack'
        sid = H_SESS(serialize_omega(omega_A) + serialize_omega(omega_B))
        if entry_A['status'] == 'active' and entry_B['status'] == 'active':
            if entry_A['sid'] == sid and entry_B['sid'] == sid:
                return True, 'already active'
            else:
                return False, 'PID already bound to different session'
        if entry_A['status'] != 'unused' or entry_B['status'] != 'unused':
            return False, 'PID not in unused state'
        if not pseudonym_verify_internal(omega_A) or not pseudonym_verify_internal(omega_B):
            return False, 'binding signature invalid'
        now = time.time()
        if omega_A['T_exp'] < now or omega_B['T_exp'] < now:
            return False, 'session material expired'
        exp_time = min(omega_A['T_exp'], omega_B['T_exp'])
        entry_A['status'] = 'active'
        entry_A['sid'] = sid
        entry_A['peer_pid'] = pid_B
        entry_A['exp_time'] = exp_time
        entry_B['status'] = 'active'
        entry_B['sid'] = sid
        entry_B['peer_pid'] = pid_A
        entry_B['exp_time'] = exp_time
        return True, 'activation success'

    def trace_malicious_pseudonym(self, malicious_PID):
        PID_m1, PID_m2 = malicious_PID
        w_i_from_pid = PID_m1[5+16:5+16+16]
        pid_hash = H(w_i_from_pid).hex()
        if pid_hash not in self.EIT_registry:
            return None
        entry = self.EIT_registry[pid_hash]
        return entry['real_id']

def serialize_omega(omg):
    pid1, pid2 = omg['PID_i']
    return pid1 + pid2 + omg['X_i'] + omg['pk_kem'] + omg['pk_sig'] + \
           omg['T_valid'].to_bytes(8,'big') + omg['T_exp'].to_bytes(8,'big')

class CarA:
    def __init__(self):
        self.real_id = str(uuid.uuid4())
        self.w_i = os.urandom(16)
        self.__temp_sk = None
        self.temp_pk = None
        self.__part_key_K = None
        self.__long_term_r = None
        self.long_term_X = None
        self.state_pool = []
        self.pool_pointer = 0
        self.__SK_i = None
        self.__kem_sk = None
        self.__sphincs_sk = None
        self.SKP_i = None
        self.omega_i = None
        self.current_phi_i = None

    def lac_generate_temp_keypair(self):
        pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_encrypt_keypair(pk, sk)
        self.temp_pk = ubyte_ptr_to_bytes(pk, CRYPTO_PUBLICKEYBYTES)
        self.__temp_sk = sk
        return self.temp_pk

    def lac_decrypt_K(self, enc):
        out = (ctypes.c_ubyte * CRYPTO_BYTES)()
        l = ctypes.c_ulonglong()
        lib.crypto_encrypt_open(out, ctypes.byref(l), bytes_to_ubyte_ptr(enc), len(enc), self.__temp_sk)
        self.__part_key_K = ubyte_ptr_to_bytes(out, l.value)
        return self.__part_key_K

    def generate_long_term_state_and_pool(self, K_i, W_i, C_i):
        self.__long_term_r = gaussian_sample()
        self.long_term_X = mat_vec_mul(MATRIX_A1, self.__long_term_r)
        self.state_pool = []
        for _ in range(100):
            phi = os.urandom(16)
            pid1 = b'PID1_' + phi + self.w_i
            pid2 = b'PID2_' + phi + self.w_i
            self.state_pool.append((phi, (pid1, pid2)))
        self.pool_pointer = 0
        self.__SK_i = {
            'K_i': K_i, 'r_i': self.__long_term_r,
            'W_i': W_i, 'C_i': C_i, 'X_i': self.long_term_X
        }
        return self.__SK_i

    def extract_pseudonym_from_pool(self):
        if self.pool_pointer >= len(self.state_pool):
            self.pool_pointer = 0
        phi, pid = self.state_pool[self.pool_pointer]
        self.current_phi_i = phi
        self.pool_pointer += 1
        return pid

    def __cls_sign(self, msg):
        max_try = 10
        for _ in range(max_try):
            y0 = gaussian_sample()
            y1 = gaussian_sample()
            t0 = mat_vec_mul(MATRIX_A0, y0)
            t1 = mat_vec_mul(MATRIX_A1, y1)
            c_bytes = H2(t0 + t1 + msg)
            c_int = int.from_bytes(c_bytes, byteorder='little')
            z0 = vec_add(y0, scalar_mul(c_int, self.__SK_i['K_i']))
            z1 = vec_add(y1, scalar_mul(c_int, self.__SK_i['r_i']))
            if vec_inf_norm(z0) <= REJECT_BOUND and vec_inf_norm(z1) <= REJECT_BOUND:
                return (z0, z1, c_bytes)
        return (z0, z1, c_bytes)

    def generate_session_key_and_sign(self, pid, valid_hours=1):
        kpk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        ksk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        lib.crypto_kem_keypair(kpk, ksk)
        kpk_b = ubyte_ptr_to_bytes(kpk, CRYPTO_PUBLICKEYBYTES)
        spk, ssk = sphincs.generate_keypair(os.urandom(48))
        self.__sphincs_sk = ssk
        self.__kem_sk = ksk
        now = int(time.time())
        exp = now + valid_hours * 3600
        pid1, pid2 = pid
        M_bind = pid1 + pid2 + self.__SK_i['X_i'] + kpk_b + spk + \
                 now.to_bytes(8,'big') + exp.to_bytes(8,'big')
        m_hash = H(M_bind)
        sig = self.__cls_sign(m_hash)
        self.SKP_i = {'sk_kem': ksk, 'sk_sig': ssk}
        self.omega_i = {
            'PID_i': pid,
            'W_i': self.__SK_i['W_i'],
            'C_i': self.__SK_i['C_i'],
            'X_i': self.__SK_i['X_i'],
            'pk_kem': kpk_b,
            'pk_sig': spk,
            'T_valid': now,
            'T_exp': exp,
            'delta_i': sig
        }
        return self.SKP_i, self.omega_i

    def car_signcrypt(self, msg, receiver_omega, YT):
        if not pseudonym_verify(receiver_omega, YT):
            raise Exception('receiver omega verification failed')
        ct_kem = (ctypes.c_ubyte * CRYPTO_CIPHERTEXTBYTES)()
        k = (ctypes.c_ubyte * CRYPTO_BYTES)()
        lib.crypto_kem_enc(ct_kem, k, bytes_to_ubyte_ptr(receiver_omega['pk_kem']))
        k_b = ubyte_ptr_to_bytes(k, CRYPTO_BYTES)
        ct_kem_b = ubyte_ptr_to_bytes(ct_kem, CRYPTO_CIPHERTEXTBYTES)
        sid = H_SESS(serialize_omega(self.omega_i) + serialize_omega(receiver_omega))
        TS = int(time.time())
        nonce = os.urandom(16)
        pid1, pid2 = self.omega_i['PID_i']
        r_pid1, r_pid2 = receiver_omega['PID_i']
        AAD = pid1 + pid2 + r_pid1 + r_pid2 + sid + TS.to_bytes(8,'big') + nonce
        sm4 = CryptSM4()
        sm4.set_key(k_b[:16], SM4_ENCRYPT)
        pad_len = 16 - len(msg) % 16
        padded_msg = msg + bytes([pad_len]) * pad_len
        c_msg = sm4.crypt_ecb(padded_msg)
        tag = H_SM3(ct_kem_b + c_msg + AAD)
        sign_input = ct_kem_b + c_msg + tag + AAD
        sign_hash = H_SM3(sign_input)
        Sig_A = sphincs.sign(sign_hash, self.__sphincs_sk)
        return {
            'omega_A': self.omega_i,
            'ct_kem': ct_kem_b,
            'c_msg': c_msg,
            'tag': tag,
            'nonce': nonce,
            'TS': TS,
            'sid': sid,
            'Sig_A': Sig_A
        }

    def verify_and_decrypt(self, pkg, YT):
        omega_A = pkg['omega_A']
        if not pseudonym_verify(omega_A, YT):
            return None
        sid_check = H_SESS(serialize_omega(omega_A) + serialize_omega(self.omega_i))
        if sid_check != pkg['sid']:
            return None
        TS = pkg['TS']
        nonce = pkg['nonce']
        c_msg = pkg['c_msg']
        tag = pkg['tag']
        Sig_A = pkg['Sig_A']
        pid1, pid2 = omega_A['PID_i']
        r_pid1, r_pid2 = self.omega_i['PID_i']
        AAD = pid1 + pid2 + r_pid1 + r_pid2 + pkg['sid'] + TS.to_bytes(8,'big') + nonce
        sign_input = pkg['ct_kem'] + c_msg + tag + AAD
        sign_hash = H_SM3(sign_input)
        if not sphincs.verify(sign_hash, Sig_A, omega_A['pk_sig']):
            return None
        if time.time() - TS > 300:
            return None
        k = (ctypes.c_ubyte * CRYPTO_BYTES)()
        lib.crypto_kem_dec(k, bytes_to_ubyte_ptr(pkg['ct_kem']), self.__kem_sk)
        k_b = ubyte_ptr_to_bytes(k, CRYPTO_BYTES)
        computed_tag = H_SM3(pkg['ct_kem'] + c_msg + AAD)
        if computed_tag != tag:
            return None
        sm4 = CryptSM4()
        sm4.set_key(k_b[:16], SM4_DECRYPT)
        padded_msg = sm4.crypt_ecb(c_msg)
        pad_len = padded_msg[-1]
        msg = padded_msg[:-pad_len]
        return msg

def pseudonym_verify_internal(omg):
    pid1, pid2 = omg['PID_i']
    z0, z1, c_bytes = omg['delta_i']
    Wi = omg['W_i']
    Xi = omg['X_i']
    current_time = time.time()
    if omg['T_exp'] < current_time or omg['T_valid'] > current_time:
        return False
    c_int = int.from_bytes(c_bytes, byteorder='little')
    t0p = vec_sub(mat_vec_mul(MATRIX_A0, z0), scalar_mul(c_int, Wi))
    t1p = vec_sub(mat_vec_mul(MATRIX_A1, z1), scalar_mul(c_int, Xi))
    M_bind = pid1 + pid2 + omg['X_i'] + omg['pk_kem'] + omg['pk_sig'] + \
             omg['T_valid'].to_bytes(8,'big') + omg['T_exp'].to_bytes(8,'big')
    m_hash = H(M_bind)
    cp_bytes = H2(t0p + t1p + m_hash)
    return c_bytes == cp_bytes

def pseudonym_verify(omg, YT):
    return pseudonym_verify_internal(omg)
