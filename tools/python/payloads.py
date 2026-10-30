# usage: payloads.py trace.log -> per "==== QUERY n" section, the keys of the mdna payload (longest toString with "75c")
import sys, re, json
sec, best = 'pre', {}
for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
    m = re.match(r'==== QUERY (\d+)', l)
    if m: sec = m.group(1); continue
    if 'JSONObject->toString' in l and '75c' in l:
        m = re.search(r'=> "?(\{.*\})"?\s*$', l.rstrip())
        if m and len(m.group(1)) > len(best.get(sec, '')): best[sec] = m.group(1)
prev = None
for sec, p in best.items():
    try: d = json.loads(p.replace('\\"', '"'))
    except Exception as e: print(sec, 'unparsed', e, p[:200]); continue
    ks = set(d)
    print(f'QUERY {sec}: {len(ks)} keys')
    if prev is not None: print('  added:', sorted(ks - prev), ' gone:', sorted(prev - ks))
    for k in ('dGh', 'kWV', 'w5v', '3k9', '8N4', 'v1X', '2mV', 'My2', 'dLH', 'ubF'):
        if k in d: print('   ', k, '=', d[k])
    prev = ks
