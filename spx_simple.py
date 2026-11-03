"""Detached SHAKE-128s-simple using the bundled SPHINCS+ reference sources."""
import ctypes as C
from pathlib import Path
L=C.CDLL(str(Path(__file__).resolve().with_name('libspx_simple.so')))
P=C.POINTER(C.c_ubyte); N=C.c_size_t
for name,args in [('crypto_sign_seed_keypair',[P,P,P]),('crypto_sign_signature',[P,C.POINTER(N),P,N,P]),('crypto_sign_verify',[P,N,P,N,P])]:
    f=getattr(L,name);f.argtypes=args;f.restype=C.c_int
def size(name):
    f=getattr(L,'crypto_sign_'+name);f.argtypes=[];f.restype=C.c_ulonglong
    return f()
crypto_sign_SEEDBYTES=size('seedbytes');crypto_sign_PUBLICKEYBYTES=size('publickeybytes')
SK=size('secretkeybytes');S=size('bytes')
if (crypto_sign_SEEDBYTES,crypto_sign_PUBLICKEYBYTES,SK,S)!=(48,32,64,7856):raise ImportError('unexpected SPHINCS+ build')
def buf(n):return (C.c_ubyte*n)()
def inp(b,n):
    if not isinstance(b,bytes) or len(b)!=n:raise ValueError('bad SPHINCS+ input')
    return (C.c_ubyte*n).from_buffer_copy(b)
def generate_keypair(seed):
    p,k=buf(32),buf(SK)
    if L.crypto_sign_seed_keypair(p,k,inp(seed,48)):raise RuntimeError('SPHINCS+ keygen')
    return bytes(p),bytes(k)
def sign(m,k):
    s,n=buf(S),N()
    if L.crypto_sign_signature(s,C.byref(n),inp(m,len(m)),len(m),inp(k,SK)) or n.value!=S:raise RuntimeError('SPHINCS+ sign')
    return bytes(s)
def verify(m,s,p):
    if len(s)!=S or len(p)!=32:return False
    return L.crypto_sign_verify(inp(s,S),S,inp(m,len(m)),len(m),inp(p,32))==0
