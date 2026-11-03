"""Research reference, Sage Python. In-process registration models a secure channel."""
from dataclasses import dataclass, astuple
from collections import deque
from threading import RLock
from secrets import token_bytes, randbelow
from math import sqrt, pi, isfinite
import hashlib, time
from math import ceil, floor, exp, isqrt
import numpy as np

def is_prime(q):
    return 2 <= q <= 2**31-1 and all(q % d for d in range(2,isqrt(q)+1))

def gaussian(center, sd):
    """Finite-window discrete Gaussian, 12 stddev, floating-point rejection."""
    lo=min(round(center),ceil(center-12*sd)); hi=max(round(center),floor(center+12*sd))
    nearest=(round(center)-center)**2
    for _ in range(4096):
        x=lo+randbelow(hi-lo+1)
        if randbelow(1<<53)/(1<<53) < exp(-max(0.,(x-center)**2-nearest)/(2*sd*sd)):
            return int(x)
    raise RuntimeError("Gaussian rejection limit")

def DG(sigma):
    return lambda: gaussian(0.,sigma)

import spx_simple as sig
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import SM4
import lac_real as lac

def pack(*xs):
    def enc(x):
        if isinstance(x,bytes): t,b=b'b',x
        elif type(x) is int: t,b=b'i',str(x).encode('ascii')
        elif isinstance(x,tuple): t,b=b't',b''.join(map(enc,x))
        else: raise TypeError(type(x))
        return t+len(b).to_bytes(8,'big')+b
    return enc(xs)
def sm3(b): return hashlib.new('sm3',b).digest()
def H(tag,*xs): return sm3(pack(tag,*xs))
def sample_hash(tag,mod,count,*xs):
    w=(mod.bit_length()+7)//8; maximum=1<<(8*w); limit=maximum-maximum%mod
    out=[]; i=0
    while len(out)<count:
        b=H(tag,*xs,i); i+=1
        for j in range(0,len(b)-w+1,w):
            v=int.from_bytes(b[j:j+w],'big')
            if v<limit: out.append(v%mod)
    return tuple(out[:count])
def keys(): return sig.generate_keypair(token_bytes(sig.crypto_sign_SEEDBYTES))
def valid(flag,msg):
    if not flag: raise ValueError(msg)
def norm(v): return max(abs(x) for p in v for x in p)

@dataclass(frozen=True)
class Config:
    # All binding parameters are explicit; none are inferred from LAC.
    n:int; q:int; u:int; trap_sd:float; preimage_sd:float; sigma:float
    beta_K:int; beta_r:int; Bz:int; retries:int=256

class Ring:
    """Single ring-row specialization: k_bind=1, m_bind=u+ceil(log2(q))."""
    def __init__(self,c):
        self.c=c; self.n=n=c.n; self.q=q=c.q
        valid(n>0 and not n&(n-1) and 2<q<2**256 and is_prime(q),'ring parameters')
        valid(c.u>0 and min(c.beta_K,c.beta_r,c.Bz,c.retries)>0 and all(isfinite(x) and x>0 for x in (c.trap_sd,c.preimage_sd,c.sigma)),'sampler parameters')
        valid(n*(c.u+q.bit_length())<=512,'dense demo basis dimension exceeds 512')
        self.l=q.bit_length();self.m=c.u+self.l
        self.zero=(0,)*n
    def mul(self,a,b):
        # Python integers: exact negacyclic product without int64 overflow.
        valid(len(a)==len(b)==self.n,'polynomial dimension')
        f=[0]*(2*self.n)
        for i,x in enumerate(a):
            for j,y in enumerate(b): f[i+j]+=int(x)*int(y)
        return tuple(f[i]-f[i+self.n] for i in range(self.n))
    def dot(self,a,b):
        valid(len(a)==len(b),'vector dimensions')
        return tuple(sum(v)%self.q for v in zip(*(self.mul(x,y) for x,y in zip(a,b))))
    def uniform(self): return tuple(randbelow(self.q) for _ in range(self.n))
    def gauss(self,D): return tuple(int(D()) for _ in range(self.n))
    def digits(self,v): return tuple(tuple(((x%self.q)>>j)&1 for x in v) for j in range(self.l))
    def W(self,pid):return sample_hash(b'H1',self.q,self.n,pid)
    def challenge(self,u,v,msg):return tuple(x-1 for x in sample_hash(b'H2',3,self.n,u,v,msg))
    def shifted(self,z,c,s,sign=1,mod=False):
        v=tuple(x+sign*y for x,y in zip(z,self.mul(c,s)))
        return tuple(x%self.q for x in v) if mod else v
    def witness(self):
        D=DG(sigma=self.c.sigma/sqrt(2*pi))
        for _ in range(self.c.retries):
            r=tuple(self.gauss(D) for _ in range(self.m))
            if norm(r)<=self.c.beta_r:return r
        raise RuntimeError('witness bound exhausted')
    def bind(self,pp,K,r,msg):
        D=DG(sigma=self.c.sigma/sqrt(2*pi))
        for _ in range(self.c.retries):
            y,v=(tuple(self.gauss(D) for _ in range(self.m)) for _ in range(2))
            c=self.challenge(self.dot(pp[0],y),self.dot(pp[1],v),msg)
            z=tuple(self.shifted(i,c,j) for i,j in zip(y,K))
            t=tuple(self.shifted(i,c,j) for i,j in zip(v,r))
            if max(norm(z),norm(t))<=self.c.Bz:return z,t,c
        raise RuntimeError('binding rejected; no signature returned')
    def verify(self,pp,o):
        z,t,c=o.delta
        valid(len(c)==self.n and all(type(x) is int and x in (-1,0,1) for x in c),'challenge')
        for v in (z,t):
            valid(len(v)==self.m and all(len(p)==self.n and all(type(a) is int for a in p) for p in v) and norm(v)<=self.c.Bz,'response')
        valid(len(o.X)==self.n and all(type(x) is int and 0<=x<self.q for x in o.X),'X encoding')
        valid(len(o.pid)==32 and len(o.kem)==lac.PK and len(o.sign)==sig.crypto_sign_PUBLICKEYBYTES,'public key length')
        u=self.shifted(self.dot(pp[0],z),c,self.W(o.pid),-1,True)
        v=self.shifted(self.dot(pp[1],t),c,o.X,-1,True)
        valid(self.challenge(u,v,o.msg())==c,'binding signature')

class KGC:
    def __init__(self,R):
        self.R=R; n,m,u,l=R.n,R.m,R.c.u,R.l
        D=DG(sigma=R.c.trap_sd)
        self.T=tuple(tuple(R.gauss(D) for j in range(l)) for i in range(u))
        a=tuple(R.uniform() for i in range(u))
        right=tuple(tuple(((1<<j)*int(h==0)-v)%R.q for h,v in enumerate(R.dot(a,[self.T[i][j] for i in range(u)]))) for j in range(l))
        self.pp=(a+right,tuple(R.uniform() for _ in range(m)))
        # Basis of ker_q([a|g]), lifted to ker_q(A0).
        rows=[]
        for i in range(u):
            for j in range(n):
                unit=tuple(int(t==j) for t in range(n))
                top=[R.zero]*u;top[i]=unit
                target=tuple(-x for x in R.mul(a[i],unit))
                rows.append(self.lift(top,R.digits(target)))
        for j in range(l):
            digits=([int(k==j)*2-int(k==j+1) for k in range(l)] if j<l-1 else [(R.q>>k)&1 for k in range(l)])
            for t in range(n):
                lower=tuple(tuple(v*int(h==t) for h in range(n)) for v in digits)
                rows.append(self.lift([R.zero]*u,lower))
        self.basis=[sum(row,()) for row in rows]
        # QR on columns gives the orthogonal directions of the ordered row basis.
        self.Q,U=np.linalg.qr(np.asarray(self.basis,dtype=float).T)
        self.diag=np.diag(U)
        valid(np.all(np.isfinite(self.diag)) and np.min(abs(self.diag))>1e-8,"unstable demo basis")
    def lift(self,top,lower):
        R=self.R
        return tuple(tuple(sum(coords) for coords in zip(v,*(R.mul(t,x) for t,x in zip(row,lower)))) for v,row in zip(top,self.T))+tuple(lower)
    def issue(self,pid):
        R=self.R; w=R.W(pid)
        s=sum(self.lift([R.zero]*R.c.u,R.digits(w)),())
        for _ in range(R.c.retries):
            # GPV-style nearest-plane sampling in s + ker(A0).
            # Only projections are floating point; updates stay exact.
            v=list(s)
            for i in reversed(range(len(v))):
                mu=-float(self.Q[:,i] @ np.asarray(v,dtype=float))/self.diag[i]
                k=gaussian(mu,R.c.preimage_sd/abs(self.diag[i]))
                v=[x+k*y for x,y in zip(v,self.basis[i])]
            K=tuple(tuple(v[i:i+R.n]) for i in range(0,len(v),R.n))
            if norm(K)<=R.c.beta_K:
                valid(R.dot(self.pp[0],K)==w,'invalid preimage')
                return K
        raise RuntimeError('partial-key sampling exhausted')

@dataclass(frozen=True)
class Omega:
    pid:bytes; X:tuple; kem:bytes; sign:bytes; start:int; exp:int; delta:tuple
    def msg(self):return pack(self.pid,self.X,self.kem,self.sign,self.start,self.exp)
    def wire(self):return pack(*astuple(self))
@dataclass(frozen=True)
class Context:
    a:Omega;b:Omega;sid:bytes;exp:int;token:bytes
    def body(self):return pack(b'ACT',self.sid,self.a.pid,self.b.pid,self.exp)
    def verify(self,pk,now):
        valid(self.sid==H(b'SID',self.a.wire(),self.b.wire()),'session mismatch')
        valid(self.exp==min(self.a.exp,self.b.exp) and max(self.a.start,self.b.start)<=now<self.exp,'inactive time')
        valid(sig.verify(self.body(),self.token,pk),'invalid activation token')
@dataclass(frozen=True)
class Payload:
    a:Omega;peer:bytes;sid:bytes;ts:int;nonce:bytes;ct:bytes;c:bytes;tag:bytes;signature:bytes
    def aad(self):return pack(self.a.pid,self.peer,self.sid,self.ts,self.nonce)
    def digest(self):return sm3(pack(self.ct,self.c,self.tag,self.aad()))

class TMA:
    def __init__(self,kgc):
        self.issuer=kgc;self.pk,self._sk=keys()
        self._ilt={};self._active={};self._lock=RLock()
    def register(self,authenticated_id,car,count,valid_until):
        # Trusted in-process boundary: caller authenticates the vehicle.
        valid(count>0 and int(time.time())<valid_until,'registration')
        with self._lock:
            for _ in range(count):
                pid=token_bytes(32); idx=H(b'ILT',pid)
                while idx in self._ilt:pid=token_bytes(32);idx=H(b'ILT',pid)
                K=self.issuer.issue(pid)
                X=car.provision(pid,K,valid_until)
                self._ilt[idx]=(pid,authenticated_id,X,valid_until,None)
    def activate(self,a,b):
        with self._lock:
            now=int(time.time());valid(a.pid!=b.pid,'distinct pseudonyms required')
            sid=H(b'SID',a.wire(),b.wire())
            for o in (a,b):
                p,_,X,end,used=self._ilt[H(b'ILT',o.pid)]
                valid(p==o.pid and X==o.X and o.start<=now<o.exp<=end,'registration mismatch/expiry')
                valid(used in (None,sid),'spent or conflicting credential')
                self.issuer.R.verify(self.issuer.pp,o)
            if sid in self._active:
                old=self._active[sid];valid((old.a,old.b)==(a,b),'activation conflict')
                return old
            from dataclasses import replace
            ctx=Context(a,b,sid,min(a.exp,b.exp),b'')
            ctx=replace(ctx,token=sig.sign(ctx.body(),self._sk))
            for o in (a,b):
                i=H(b'ILT',o.pid);self._ilt[i]=self._ilt[i][:-1]+(sid,)
            self._active[sid]=ctx
            return ctx
    def trace(self,p,acceptance_time):
        # Time must come from the authenticated historical evidence record.
        ctx=self._active[p.sid];ctx.verify(self.pk,acceptance_time)
        check_payload(p,ctx,acceptance_time)
        self.issuer.R.verify(self.issuer.pp,p.a)
        pid,owner,X,_,used=self._ilt[H(b'ILT',p.a.pid)]
        valid(pid==p.a.pid and X==p.a.X and used==p.sid,'ownership mismatch')
        return owner

def check_payload(p,ctx,now):
    valid(p.a==ctx.a and p.peer==ctx.b.pid and p.sid==ctx.sid,'wrong activated context')
    valid(max(ctx.a.start,ctx.b.start)<=p.ts<=now<ctx.exp and now-p.ts<=300,'freshness')
    valid(len(p.nonce)==12 and len(p.tag)==16 and len(p.ct)==lac.CT,'packet lengths')
    valid(sig.verify(p.digest(),p.signature,ctx.a.sign),'payload signature')

class Vehicle:
    def __init__(self,R,pp,tma_pk):
        self.R=R;self.pp=pp;self.ta=tma_pk
        self.pool=deque();self.private={};self.contexts={};self.seen=set();self.lock=RLock()
    def provision(self,pid,K,end):
        valid(self.R.dot(self.pp[0],K)==self.R.W(pid) and norm(K)<=self.R.c.beta_K,'partial credential')
        r=self.R.witness();X=self.R.dot(self.pp[1],r)
        self.pool.append((pid,K,r,X,end));return X
    def session_config(self,lifetime):
        from dataclasses import replace
        pid,K,r,X,end=self.pool.popleft()
        now=int(time.time());exp=min(now+lifetime,end);valid(now<exp,'expired')
        pk,sk=lac.keypair();vk,ss=keys()
        o=Omega(pid,X,pk,vk,now,exp,())
        o=replace(o,delta=self.R.bind(self.pp,K,r,o.msg()))
        self.private[pid]=(o,sk,ss);return o
    def accept_activation(self,ctx):
        ctx.verify(self.ta,int(time.time()))
        valid(any(o.pid in self.private and self.private[o.pid][0]==o for o in (ctx.a,ctx.b)),'wrong endpoint')
        self.contexts[ctx.sid]=ctx
    def signcrypt(self,sid,msg):
        from dataclasses import replace
        ctx=self.contexts[sid];now=int(time.time());ctx.verify(self.ta,now)
        o,_,sk=self.private[ctx.a.pid];valid(o==ctx.a,'wrong sender')
        ct,k=lac.encap(ctx.b.kem);nonce=token_bytes(12)
        p=Payload(o,ctx.b.pid,sid,now,nonce,ct,b'',b'',b'')
        enc=Cipher(SM4(k[:16]),modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(p.aad())
        p=replace(p,c=enc.update(msg)+enc.finalize(),tag=enc.tag)
        return replace(p,signature=sig.sign(p.digest(),sk))
    def unsigncrypt(self,p):
        with self.lock:
            now=int(time.time());ctx=self.contexts[p.sid];ctx.verify(self.ta,now)
            o,sk,_=self.private[ctx.b.pid];valid(o==ctx.b,'wrong receiver')
            check_payload(p,ctx,now);key=(p.sid,p.nonce);valid(key not in self.seen,'replay')
            k=lac.decap(sk,p.ct)
            dec=Cipher(SM4(k[:16]),modes.GCM(p.nonce,p.tag)).decryptor()
            dec.authenticate_additional_data(p.aad())
            msg=dec.update(p.c)+dec.finalize();self.seen.add(key)
            return msg
