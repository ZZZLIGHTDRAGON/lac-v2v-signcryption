"""Benchmark the CPython V2V_VSCode prototype; all reported times are local measurements."""
import argparse
import csv
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict
from pathlib import Path
import numpy
import cryptography
import lac_real as lac
from lac_car_kgc import Config, Ring, KGC, TMA, Vehicle

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sessions', type=int, default=10)
    parser.add_argument('--messages', type=int, default=1, help='messages per session')
    parser.add_argument('--bytes', type=int, default=256, dest='size')
    parser.add_argument('--warmup', type=int, default=1, help='unreported complete sessions')
    parser.add_argument('--out', type=Path, default=None)
    args = parser.parse_args()
    if min(args.sessions,args.messages)<1 or min(args.size,args.warmup)<0:
        parser.error('invalid counts or payload size')
    out=args.out or Path('results')/str(time.time_ns())
    out.mkdir(parents=True,exist_ok=False)
    cfg=Config(n=4,q=12289,u=2,trap_sd=1.,preimage_sd=48.,sigma=4.,beta_K=300,beta_r=12,Bz=1000)
    ring=Ring(cfg); kgc=KGC(ring); ta=TMA(kgc)
    a,b=(Vehicle(ring,kgc.pp,ta.pk) for _ in range(2))
    msg=b'V'*args.size
    metadata=dict(binding=asdict(cfg),sessions=args.sessions,messages_per_session=args.messages,
                  warmup_sessions=args.warmup,payload_bytes=args.size,
                  python=sys.version,platform=platform.platform(),numpy=numpy.__version__,
                  cryptography=cryptography.__version__,lac_ct_bytes=lac.CT,
                  clock='perf_counter_ns',profile='toy binding; in-process; no network',
                  setup='Ring/KGC/TMA/Vehicle creation excluded; registry grows by two states per session')
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf8')
    samples={}
    with (out/'raw.csv').open('w',newline='') as f:
        writer=csv.writer(f);writer.writerow(['session','message','operation','elapsed_ns'])
        for i in range(-args.warmup,args.sessions):
            j=None
            def timed(name,fn,*params):
                start=time.perf_counter_ns()
                value=fn(*params)
                elapsed=time.perf_counter_ns()-start
                if i>=0:
                    writer.writerow([i+1,j,name,elapsed])
                    samples.setdefault(name,[]).append(elapsed/1e6)
                return value
            end=int(time.time())+86400
            timed('register_A_one_state',ta.register,'Vehicle-A',a,1,end)
            timed('register_B_one_state',ta.register,'Vehicle-B',b,1,end)
            oa=timed('session_config_A',a.session_config,3600)
            ob=timed('session_config_B',b.session_config,3600)
            timed('standalone_binding_verify_A',ring.verify,kgc.pp,oa)
            ctx=timed('TMA_activate_both',ta.activate,oa,ob)
            timed('accept_activation_A',a.accept_activation,ctx)
            timed('accept_activation_B',b.accept_activation,ctx)
            for j in range(1,args.messages+1):
                p=timed('signcrypt',a.signcrypt,ctx.sid,msg)
                plain=timed('unsigncrypt',b.unsigncrypt,p)
                accepted=int(time.time())
                if plain!=msg: raise RuntimeError('plaintext mismatch')
                owner=timed('complete_trace',ta.trace,p,accepted)
                if owner!='Vehicle-A': raise RuntimeError('incorrect trace')
            f.flush()
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.writer(f);w.writerow(['operation','count','mean_ms','median_ms','p95_ms','min_ms','max_ms'])
        for name,x in samples.items():
            stats=[statistics.mean(x),statistics.median(x),numpy.percentile(x,95),min(x),max(x)]
            w.writerow([name,len(x),*[f'{v:.6f}' for v in stats]])
            print(f'{name:30s} n={len(x):4d}  mean={stats[0]:9.3f} ms')
    print('Results:',out.resolve())

if __name__=='__main__':
    main()
