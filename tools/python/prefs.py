# usage: prefs.py trace.log -> the SDK's prefs at the end of the harness run, names un-hashed and values decoded
import hashlib, base64, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elf, funcstr, keysites
_data = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'sample', 'libdu.so'), 'rb').read()
_got = elf.relative(_data)
names = {s for _, s, _ in keysites.key_loads(_data, _got)}  # every decoded string is a candidate pref name
for strs in funcstr.strings_by_func(_data, _got, elf.funcs(_data)).values(): names.update(strs)
names |= {'fut', 'lut', 'boot_times', 'mtr', 'ndcd', 'pkcg', 'n_a', 'o_a', 'aid', 'imdrt', 'device_label', 'device_id', 'nctl', 'sid', 'cdd', 'ioaid'} | {f'i{i}' for i in range(1, 10)}
H = {hashlib.md5(n.encode('utf-8')).hexdigest().upper(): n for n in names}
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
