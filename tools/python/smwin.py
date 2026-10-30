# usage: smwin.py sm.txt <state_hex> [depth]  -> the states reachable from <state> within depth, readable
import sys, re, collections
lines = open(sys.argv[1], encoding='utf-8').read().splitlines()
edges = collections.OrderedDict(); cur = None
for l in lines:
    m = re.match(r'S([0-9a-f]{8}):', l)
    if m: cur = m.group(1); edges[cur] = []; continue
    m = re.match(r'\s+-> (\S+)( if (.*?))?(   \[(.*)\])?$', l)
    if m and cur:
        dst = m.group(1)[1:] if m.group(1).startswith('S') else m.group(1)
        edges[cur].append((dst, m.group(3) or '', m.group(5) or ''))
start = sys.argv[2].lower().lstrip('s').rjust(8, '0'); depth = int(sys.argv[3]) if len(sys.argv) > 3 else 12
seen = {start: 0}; q = collections.deque([start]); order = []
while q:
    s = q.popleft(); order.append(s)
    if seen[s] >= depth: continue
    for d, _, _ in edges.get(s, []):
        if d not in seen and d in edges: seen[d] = seen[s] + 1; q.append(d)
for s in order:
    print(f'S{s}:')
    grp = collections.OrderedDict()
    for d, c, ev in edges.get(s, []): grp.setdefault((d, ev), []).append(c)
    for (d, ev), cs in grp.items():
        cs = sorted(set(cs)); cond = '' if cs == [''] else ' if ' + ' | '.join(f'({c})' for c in cs[:3]) + (f' +{len(cs)-3}' if len(cs) > 3 else '')
        print(f'   -> {d}{cond}' + (f'\n        {ev}' if ev else ''))
