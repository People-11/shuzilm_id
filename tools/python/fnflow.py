# usage: fnflow.py trace.log func_strings.txt [start_hex]  -> FN sequence (collapsed) with string hints, JNI calls inline
import sys, re
idx = {}
for l in open(sys.argv[2], encoding='latin1'):
    a, s = l.split('\t', 1); idx[int(a, 16)] = s.strip()[:110]
started = len(sys.argv) < 4
prev = None
for l in open(sys.argv[1], encoding='utf-8'):
    m = re.match(r'FN (0x[0-9a-f]+).*lr=(0x[0-9a-f]+)', l)
    if m:
        f = int(m.group(1), 16)
        if not started and f == int(sys.argv[3], 16): started = True
        if not started or f in (0x1143bc, 0xf5348, 0xf5c28, 0xf5f20, 0xf71b8, 0xf7cd8, 0xf53f0, 0xf51d8, 0xf5088): continue
        if f == prev: continue
        prev = f
        print(f"FN {m.group(1)} <- {m.group(2)}  {idx.get(f, '')}")
    elif started and not l.startswith('   '):
        print('   ' + l.rstrip()[:160])
