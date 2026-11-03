#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
src=$(cd "${1:-$here/vendor/LAC-ref}" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$src"/*.c "$src"/*.h "$tmp/"
cd "$tmp"
# Replace the submission's KAT random stream with the OS-seeded OpenSSL RNG.
python3 - <<'PY'
from pathlib import Path
p=Path('rand.c');s=p.read_text();old='randombytes(r,len);'
if s.count(old)!=1: raise SystemExit('Unexpected rand.c; inspect RNG before building')
p.write_text(s.replace(old,'if (RAND_bytes(r,len) != 1) abort();').replace('#include "rand.h"','#include <stdlib.h>\n#include "rand.h"'))
PY
cat > sizes.c <<'C'
#include "api.h"
#if !defined(LAC128) || DIM_N != 512 || Q != 251
#error Expected attached LAC128 reference parameter set
#endif
int v2v_lac_size(int i){ const int s[]={CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_CIPHERTEXTBYTES,CRYPTO_BYTES};return s[i]; }
C
cc -O2 -fPIC -shared -o "$here/liblac_v2v.so" sizes.c kem.c encrypt.c ecc.c bch.c bin-lwe.c rand.c rng.c -lcrypto
tar -xzf "$here/vendor/PySPX-0.5.0.tar.gz" -C "$tmp" PySPX-0.5.0/src/sphincsplus/ref
cd "$tmp/PySPX-0.5.0/src/sphincsplus/ref"
cc -O2 -fPIC -shared -DPARAMS=sphincs-shake-128s -o "$here/libspx_simple.so" \
  address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c fips202.c hash_shake.c thash_shake_simple.c
