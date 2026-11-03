"""VS Code entry point. Toy binding configuration, not a benchmark."""
import time
from lac_car_kgc import Config, Ring, KGC, TMA, Vehicle

def main():
    config=Config(n=4,q=12289,u=2,trap_sd=1.,preimage_sd=48.,
                  sigma=4.,beta_K=300,beta_r=12,Bz=1000)
    ring=Ring(config)
    kgc=KGC(ring)
    tma=TMA(kgc)
    a,b=(Vehicle(ring,kgc.pp,tma.pk) for _ in range(2))
    end=int(time.time())+3600
    tma.register("Vehicle-A",a,1,end)
    tma.register("Vehicle-B",b,1,end)
    print("1. 双方已注册，部分密钥与假名的原像等式已检查。")
    oa,ob=a.session_config(600),b.session_config(600)
    ctx=tma.activate(oa,ob)
    a.accept_activation(ctx)
    b.accept_activation(ctx)
    print("2. 双方绑定与注册分量已验证，会话已激活。",ctx.sid.hex()[:16])
    msg="前方车辆减速".encode()
    p=a.signcrypt(ctx.sid,msg)
    plain=b.unsigncrypt(p)
    accepted=int(time.time())
    if plain!=msg: raise RuntimeError("plaintext mismatch")
    print("3. 接收方验签、解封装和 GCM 解密成功：",plain.decode())
    owner=tma.trace(p,accepted)
    if owner!="Vehicle-A": raise RuntimeError("wrong owner")
    print("4. 争议追踪返回注册发送者：",owner)

if __name__=="__main__":
    main()
