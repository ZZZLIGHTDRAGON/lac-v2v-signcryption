"""ILT scaling: valid archived evidence; real registration outside timed regions."""
import argparse
import csv
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict
from pathlib import Path
import numpy as np
from lac_car_kgc import Config, Ring, KGC, TMA, Vehicle, H

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sizes',nargs='+',type=int,default=[100,500,1000,5000,10000])
    ap.add_argument('--repeats',type=int,default=30)
    ap.add_argument('--lookup-batch',type=int,default=1000)
    ap.add_argument('--out',type=Path,default=None)
    args=ap.parse_args()
    if min(args.sizes)<2 or min(args.repeats,args.lookup_batch)<1:
        ap.error('sizes >=2; repeats and lookup-batch >=1')
    sizes=sorted(set(args.sizes))
    out=args.out or Path('results')/f'ilt_scale_{time.time_ns()}'
    out.mkdir(parents=True,exist_ok=False)
    cfg=Config(n=4,q=12289,u=2,trap_sd=1.,preimage_sd=48.,
               sigma=4.,beta_K=300,beta_r=12,Bz=1000)
    ring=Ring(cfg);kgc=KGC(ring);ta=TMA(kgc)
    a,b=(Vehicle(ring,kgc.pp,ta.pk) for _ in range(2))
    end=int(time.time())+86400
    ta.register('Vehicle-A',a,1,end);ta.register('Vehicle-B',b,1,end)
    oa,ob=a.session_config(3600),b.session_config(3600)
    ctx=ta.activate(oa,ob)
    a.accept_activation(ctx);b.accept_activation(ctx)
    msg=b'V'*256
    packet=a.signcrypt(ctx.sid,msg)
    if b.unsigncrypt(packet)!=msg:raise RuntimeError('message correctness')
    acceptance_time=int(time.time())

    # ========= 最小修改：lookup改为只读，不再校验used =========
    def lookup():
        # Includes PID hashing, dictionary access, and registration comparisons.
        # Excludes signatures and historical evidence verification.
        pid,owner,X,_,used=ta._ilt[H(b'ILT',packet.a.pid)]
        if pid!=packet.a.pid or X!=packet.a.X:
            raise RuntimeError('ownership mismatch')
        return owner

    # ========= 新增只读trace，复刻ta.trace逻辑，不写入used状态 =========
    def trace_ro():
        sid = packet.sid
        ctx_local = ta._active[sid]
        ctx_local.verify(ta.pk, acceptance_time)
        pid = packet.a.pid
        idx = H(b'ILT', pid)
        pid_stored, owner, X, valid_until, used_flag = ta._ilt[idx]
        if pid_stored != pid or X != packet.a.X:
            raise RuntimeError('ownership mismatch')
        return owner

    metadata=dict(binding=asdict(cfg),sizes=sizes,repeats=args.repeats,
        lookup_batch=args.lookup_batch,python=sys.version,platform=platform.platform(),
        scope='same valid accepted packet and target entry at every N; warm-cache repeated access',
        registry='real registration, increasing total PID entries including both challenge vehicles',
        excluded='setup, registration, table growth, network and disk',
        historical_acceptance_time=acceptance_time,
        limitations='toy binding; in-process single-thread registry; not a complexity proof; trace is read-only variant for benchmark')
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf8')
    rows=[]
    with (out/'raw.csv').open('w',newline='') as raw:
        w=csv.writer(raw)
        w.writerow(['N','repetition','operation','batch_count','batch_ns','per_call_ms'])
        for N in sizes:
            print(f'Growing ILT to {N} total PID entries...',flush=True)
            while len(ta._ilt)<N:
                # Real dummy-owner credentials, not dummy tracing evidence.
                # Temporary object released after registration to avoid retaining
                # every background private state in the benchmark.
                count=min(100,N-len(ta._ilt))
                filler=Vehicle(ring,kgc.pp,ta.pk)
                ta.register(f'Background-{len(ta._ilt)}',filler,count,end)
                del filler
                print(f'  registered {len(ta._ilt)}/{N}',flush=True)
            if len(ta._ilt)!=N:raise RuntimeError('wrong registry size')
            for _ in range(3):
                if trace_ro()!='Vehicle-A' or lookup()!='Vehicle-A':
                    raise RuntimeError('warmup failed')
            measurements={'complete_trace':[],'indexed_ownership_check':[]}
            for rep in range(args.repeats):
                # Alternate order to reduce fixed ordering bias.
                jobs=[('complete_trace',trace_ro,1),
                      ('indexed_ownership_check',lookup,args.lookup_batch)]
                if rep%2:jobs.reverse()
                for name,fn,batch in jobs:
                    start=time.perf_counter_ns()
                    for _ in range(batch):
                        owner=fn()
                        if owner!='Vehicle-A':raise RuntimeError('wrong traced identity')
                    elapsed=time.perf_counter_ns()-start
                    ms=elapsed/batch/1e6
                    measurements[name].append(ms)
                    w.writerow([N,rep+1,name,batch,elapsed,f'{ms:.9f}'])
            for name,v in measurements.items():
                row=[N,name,len(v),statistics.mean(v),statistics.median(v),
                     float(np.percentile(v,95)),min(v),max(v)]
                rows.append(row)
                print(f'{name}: mean={row[3]:.6f} ms, median={row[4]:.6f} ms',flush=True)
            raw.flush()
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.writer(f)
        w.writerow(['N','operation','samples','mean_ms','median_ms','p95_ms','min_ms','max_ms'])
        w.writerows(rows)
    print('Results:',out.resolve())

if __name__=='__main__':
    main()
