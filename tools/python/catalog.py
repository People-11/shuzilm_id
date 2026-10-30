# usage: catalog.py payload_*.txt -> TSV: key, reports it appears in, sample value, value decoded as mode 2/3
# (shuffle^-1 then char-1) when that looks like text, plus nested objects flattened as parent.key
import sys, re, json, os

def unenc(e):
    n = len(e); m = n // 2; s = [''] * n; k = 0
    if n % 2: s[m] = e[0]; k = 1
    for i in range(m): s[n - 1 - i] = e[k]; s[m - 1 - i] = e[k + 1]; k += 2
    return ''.join(chr(ord(c) - 1) for c in s)

def load(path):
    t = open(path, encoding='utf-8').read().strip()
    if t.startswith('"') and t.endswith('"'): t = t[1:-1]
    return json.loads(t)

def walk(d, pre, out):
    for k, v in d.items():
        key = pre + k
        if isinstance(v, dict): out[key] = '{...}'; walk(v, key + '.', out)
        else: out[key] = v

cat = {}
for p in sys.argv[1:]:
    rep = re.search(r'payload_(\w+)', os.path.basename(p)).group(1)
    flat = {}
    try: walk(load(p), '', flat)
    except Exception as e: print('#', p, e, file=sys.stderr); continue
    for k, v in flat.items():
        c = cat.setdefault(k, {'reps': [], 'v': v}); c['reps'].append(rep)
for k in sorted(cat, key=lambda x: x.lower()):
    v = cat[k]['v']; dec = ''
    if isinstance(v, str) and len(v) > 1:
        u = unenc(v)
        if all(32 <= ord(ch) < 127 for ch in u) and u != v: dec = u
    print(f"{k}\t{','.join(cat[k]['reps'])}\t{str(v)[:70]}\t{dec[:70]}")
