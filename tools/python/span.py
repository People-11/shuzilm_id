# usage: span.py trace.log func_strings.txt START_SUBSTR END_SUBSTR  -> FN flow between two trace markers
import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
lines = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')
s = next(i for i, l in enumerate(lines) if sys.argv[3] in l)
e = next(i for i, l in enumerate(lines) if i > s and sys.argv[4] in l)
idx = {}
for l in open(sys.argv[2], encoding='latin1'):
    a, t = l.split('\t', 1); idx[int(a, 16)] = t.strip()[:90]
skip = {0x1143bc, 0xf5348, 0xf5c28, 0xf5f20, 0xf71b8, 0xf7cd8, 0xf53f0, 0xf51d8, 0xf5088, 0xdc18c, 0xdc4cc, 0xf55d8, 0xf5634, 0xf5830, 0xf59a8, 0xf5bc0}
prev = None
for l in lines[s:e + 1]:
    m = re.match(r'FN (0x[0-9a-f]+) x0=(\S+) x1=(\S+) x2=(\S+) lr=(\S+)', l)
    if m:
        f = int(m.group(1), 16)
        if f in skip or f == prev: continue
        prev = f
        print(f"{f:#x} x0={m.group(2)} x1={m.group(3)} x2={m.group(4)} <- {m.group(5)}  {idx.get(f, '')}")
    elif not l.startswith('   '):
        print('   J', ascii(l[:160]))
