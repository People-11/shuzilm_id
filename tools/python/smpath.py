# usage: smpath.py sm.txt <pc_hex|text>  -> states whose handler does it, and the shortest path from the start to each
import sys, re, collections
lines = open(sys.argv[1], encoding='utf-8').read().splitlines()
start = re.search(r'start state 0x([0-9a-f]+)', lines[0]).group(1).rjust(8, '0')
edges = collections.defaultdict(list); body = {}
cur = None
for l in lines[1:]:
    m = re.match(r'S([0-9a-f]{8}):', l)
    if m: cur = m.group(1); continue
    m = re.match(r'\s+-> (\S+)(.*)', l)
    if m and cur:
        dst = m.group(1)[1:] if m.group(1).startswith('S') else m.group(1)
        edges[cur].append((dst, m.group(2)))
q = sys.argv[2]
hits = [s for s, es in edges.items() if any(q in t for _, t in es)]
prev = {start: None}; dq = collections.deque([start])
while dq:
    s = dq.popleft()
    for d, t in edges.get(s, []):
        if d not in prev: prev[d] = (s, t); dq.append(d)
for h in hits:
    print('=== hit', h)
    path = []; s = h
    while prev.get(s):
        p, t = prev[s]; path.append((p, t)); s = p
    if s != start: print('  unreachable from start'); continue
    for p, t in reversed(path): print(f'  S{p}{t[:400]}')
    for d, t in edges[h]: print(f'  ** S{h} -> {d}{t[:400]}')
