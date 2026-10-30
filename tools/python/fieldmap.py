# usage: fieldmap.py trace.log payload.json  -> for each payload key: value + data reads since the previous JSON put
import sys, re, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
keys = set(json.load(open(sys.argv[2], encoding='utf-8')).keys())
put = re.compile(r'^CALL org/json/JSONObject->put\(Ljava/lang/String;(.)\)?.*? args=\["([^"]*)", (.*?), \] => ')
noise = ('MessageDigest', 'String->getBytes', 'getPackageName()', 'getSharedPreferences', 'JSONObject->opt', 'JSONObject-><init>', 'JSONObject->toString')
buf = []
seen = {}
for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
    l = l.rstrip('\n')
    m = re.match(r'^CALL org/json/JSONObject->put\(Ljava/lang/String;([^)]*)\).*?args=\["([^"]*)", (.*), \] => ', l)
    if m:
        k, v = m.group(2), m.group(3)
        if k in keys and k not in seen:
            seen[k] = (v[:120], buf[-14:])
        buf = []
        continue
    if l.startswith(('CALL', 'GET', 'PROP', 'SYSCALL openat', 'SET')) and not any(n in l for n in noise):
        l = re.sub(r' on [^ ]+\{[^}]{0,200}\}', '', l)
        buf.append(l[:170])
for k in sorted(seen, key=lambda x: x.lower()):
    v, ev = seen[k]
    print(f'== {k} = {v}')
    for e in ev: print('     ' + e)
print('missing:', sorted(keys - set(seen)))
