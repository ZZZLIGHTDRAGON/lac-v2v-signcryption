"""ctypes interface for the accompanying LAC reference build (Linux)."""
import ctypes as C
from pathlib import Path
from hmac import compare_digest

lib = C.CDLL(str(Path(__file__).resolve().with_name("liblac_v2v.so")))
U = C.c_ubyte
P = C.POINTER(U)
L = C.c_ulonglong
lib.v2v_lac_size.argtypes = [C.c_int]
lib.v2v_lac_size.restype = C.c_int
PK, SK, CT, SS = (lib.v2v_lac_size(i) for i in range(4))
if (PK, SK, CT, SS) != (544, 1056, 1024, 32):
    raise ImportError("unexpected LAC build")
for name, args in {
    "crypto_kem_keypair":[P,P], "crypto_kem_enc":[P,P,P],
    "crypto_kem_dec":[P,P,P], "crypto_encrypt_keypair":[P,P],
    "crypto_encrypt":[P,C.POINTER(L),P,L,P],
    "crypto_encrypt_open":[P,C.POINTER(L),P,L,P],
}.items():
    f=getattr(lib,name); f.argtypes=args; f.restype=C.c_int

def buf(n): return (U*n)()
def arg(x,n):
    if not isinstance(x,bytes) or len(x)!=n: raise ValueError("invalid LAC input length")
    return (U*n).from_buffer_copy(x)
def check(rc):
    if rc: raise ValueError(f"LAC returned {rc}")
def keypair(*,pke=False):
    p,s=buf(PK),buf(SK)
    check((lib.crypto_encrypt_keypair if pke else lib.crypto_kem_keypair)(p,s))
    return bytes(p),bytes(s)
def encap(pk):
    c,k=buf(CT),buf(SS)
    check(lib.crypto_kem_enc(c,k,arg(pk,PK)))
    return bytes(c),bytes(k)
def decap(sk,ct):
    k=buf(SS);check(lib.crypto_kem_dec(k,arg(ct,CT),arg(sk,SK)))
    return bytes(k)
def encrypt(pk,message):
    if not isinstance(message,bytes) or not 1<=len(message)<=SS: raise ValueError("PKE supports 1..32 bytes here")
    c,n=buf(CT),L();check(lib.crypto_encrypt(c,C.byref(n),arg(message,len(message)),len(message),arg(pk,PK)))
    if n.value!=CT: raise ValueError("invalid PKE output length")
    return bytes(c)
def decrypt(sk,ct):
    m,n=buf(SS),L();check(lib.crypto_encrypt_open(m,C.byref(n),arg(ct,CT),CT,arg(sk,SK)))
    if n.value>SS: raise ValueError("invalid PKE plaintext length")
    return bytes(m[:n.value])
