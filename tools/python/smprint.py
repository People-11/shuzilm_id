# usage: smprint.py sm.txt  -> the state machine as a readable listing: states in DFS order from the start, chains of
# event-less single-successor states collapsed, each edge with its condition and the calls made on the way
import sys, re, collections
lines = open(sys.argv[1], encoding='utf-8').read().splitlines()
start = None
edges = collections.OrderedDict(); cur = None
for l in lines:
    m = re.search(r'start state 0x([0-9a-f]+)', l)
    if m: start = m.group(1).rjust(8, '0'); continue
    m = re.match(r'S([0-9a-f]{8}):', l)
    if m: cur = m.group(1); edges[cur] = []; continue
    m = re.match(r'\s+-> (\S+)( if (.*?))?(   \[(.*)\])?$', l)
    if m and cur:
        dst = m.group(1)[1:] if m.group(1).startswith('S') else m.group(1)
        edges[cur].append((dst, m.group(3) or '', m.group(5) or ''))

def simple(s):  # one successor, no calls
    es = edges.get(s, [])
    dsts = {d for d, _, _ in es}
    return len(dsts) == 1 and all(not ev for _, _, ev in es)

def follow(s):
    seen = set()
    while s in edges and simple(s) and s not in seen:
        seen.add(s); s = edges[s][0][0]
    return s

done = set(); order = []
stack = [start]
while stack:
    s = follow(stack.pop())
    if s in done or s not in edges: continue
    done.add(s); order.append(s)
    for d, _, _ in reversed(edges[s]): stack.append(d)
for s in order:
    print(f'S{s}:')
    # group edges by (dst, events) and show distinct conditions
    grp = collections.OrderedDict()
    for d, c, ev in edges[s]:
        grp.setdefault((follow(d) if d in edges else d, ev), []).append(c)
    for (d, ev), cs in grp.items():
        cs = sorted(set(cs))
        cond = '' if cs == [''] or len(cs) > 3 else ' if ' + ' | '.join(f'({c})' for c in cs)
        if len(cs) > 3: cond = f' if <{len(cs)} variants>'
        print(f'   -> {"S" + d if re.match("[0-9a-f]{8}$", d) else d}{cond}')
        if ev: print(f'        {ev}')
