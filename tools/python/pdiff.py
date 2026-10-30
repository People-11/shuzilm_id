# usage: pdiff.py trace.log [kind=mdna]  -> mdna payload keys per QUERY section of a QUERIES=n harness run, and what changed
import re, sys
KIND = sys.argv[2] if len(sys.argv) > 2 else 'mdna'
secs = {}; sec = None; last = ''
for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
    m = re.match(r'==== QUERY (\d+)', l)
    if m: sec = m.group(1); continue
    if sec and 'JSONObject->toString' in l and '"75c"' in l:
        m = re.search(r'=> (.*)$', l.rstrip())
        if m and len(m.group(1)) > len(last): last = m.group(1)
    if sec and l.startswith('NET URL') and '/' + KIND + '/' in l:
        secs.setdefault(sec, last); last = ''
    elif l.startswith('NET URL'): last = ''
pat = re.compile(r'"(\w{2,4})":("(?:[^"\\]|\\.)*"|-?\d+|\{)')
ks = {s: dict(pat.findall(p)) for s, p in secs.items()}
order = sorted(ks, key=int, reverse=True)
for x, y in zip(order, order[1:]):
    a, b = ks[x], ks[y]
    print(f'query {x}: {len(a)} keys, query {y}: {len(b)} keys; added {sorted(set(b) - set(a))}, gone {sorted(set(a) - set(b))}')
    for k in sorted(set(b) - set(a)): print('   ', k, b[k][:90])
    for k in sorted(set(a) & set(b)):
        if a[k] != b[k]: print('    changed', k, a[k][:50], '->', b[k][:50])
