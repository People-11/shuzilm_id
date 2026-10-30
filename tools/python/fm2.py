# usage: fm2.py trace.log KEY [KEY...]  -> for each put of KEY: its value and the data reads (JNI calls, field gets,
# props, opened files) since the previous put, which is where the value came from
import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
keys = set(sys.argv[2:])
noise = ('MessageDigest', 'String->getBytes', 'JSONObject->opt', 'JSONObject-><init>', 'JSONObject->toString',
         'DeleteLocalRef', 'JSONObject->has')
buf, done = [], set()
for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
    l = l.rstrip('\n')
    m = re.match(r'^CALL org/json/JSONObject->put\(Ljava/lang/String;[^)]*\).*?args=\["([^"]*)", (.*), \] => ', l)
    if m:
        k, v = m.group(1), m.group(2)
        if k in keys and k not in done:
            done.add(k)
            print(f'== {k} = {v[:150]}')
            for e in buf[-12:]: print('     ' + e[:200])
        buf = []
        continue
    if l.startswith(('CALL', 'GET', 'PROP', 'SYSCALL openat', 'SET', 'RICH', 'THROW')) and not any(n in l for n in noise):
        buf.append(re.sub(r' on [^ ]+\{[^}]{0,120}\}', '', l))
print('not seen:', sorted(keys - done))
