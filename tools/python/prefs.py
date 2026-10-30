# usage: prefs.py trace.log -> the SDK's prefs at the end of the harness run, names un-hashed and values decoded
import hashlib, base64, re, ast, sys, os
names = set()
_D = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
for f in (os.path.join(_D, 'strings.txt'), os.path.join(_D, 'keysites.txt')):
    for l in open(f, encoding='latin1'):
        m = re.search(r"'(.*)'\s*\S*$", l.rstrip('\n'))
        if m:
            try: names.add(ast.literal_eval("'" + m.group(1) + "'"))
            except Exception: pass
names |= {'fut', 'lut', 'boot_times', 'mtr', 'ndcd', 'pkcg', 'n_a', 'o_a', 'aid', 'imdrt', 'device_label', 'device_id', 'nctl', 'sid', 'cdd', 'ioaid'} | {f'i{i}' for i in range(1, 10)}
H = {hashlib.md5(n.encode('latin1')).hexdigest().upper(): n for n in names}
def dec(v):
    try:
        t = base64.b64decode(v).decode('latin1')
        return t[32:] + ('' if hashlib.md5(t[32:].encode('latin1')).hexdigest().upper() == t[:32] else ' (no md5)')
    except Exception: return v + ' (raw)'
on = False
for l in open(sys.argv[1], encoding='utf-8'):
    if l.startswith('==== PREFS'): on = True; continue
    if l.startswith('==== MISSES'): break
    m = re.match(r'(\S+) \| (\S+) = (.*)', l.rstrip('\n'))
    if on and m:
        f, k, v = m.groups()
        print(f'{f:28} {H.get(k, k):14} = {dec(v) if f.endswith("_prefs") else v}')
