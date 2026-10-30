# usage: decode_payload.py trace.log  -> the mdna plaintext JSON (first one containing "75c") with encoded fields decoded
import sys, re, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
t = open(sys.argv[1], encoding='utf-8', errors='replace').read()
m = re.search(r'JSONObject->toString\(\)Ljava/lang/String; on org/json/JSONObject\{.*?\} args=\[\] => "(\{.*?"75c".*?)"\n', t)
d = json.loads(m.group(1))
def unshuffle(o):
    n = len(o); h = n // 2; s = [None] * n; k = 0
    if n % 2: s[h] = o[0]; k = 1
    for i in range(h): s[n-1-i] = o[k]; s[h-1-i] = o[k+1]; k += 2
    return ''.join(s)
dec = lambda v: ''.join(chr(ord(c) - 1) for c in unshuffle(v))
ENC = {'UOv', 'R1e', 'ibF', '52J', 'dLH', 'H4S', 'AWo', 'LAh', '90P'}
def walk(o, pre=''):
    for k, v in o.items():
        if isinstance(v, dict): walk(v, pre + k + '.')
        elif k in ENC and isinstance(v, str): print(f'{pre}{k:6} = {v!r:45} -> {dec(v)!r}')
        else: print(f'{pre}{k:6} = {v!r}')
walk(d)
