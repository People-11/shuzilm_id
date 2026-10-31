# usage: extract_payloads.py trace.log outdir
# The plaintext of every report a harness run sent: the JSON handed to compress() (COMPRESS@... in[n]=hex) right
# before each NET URL, written as outdir/payload_<kind>.json for the first report of each kind (mdna, d2api, ...).
# The host's apiKey (field 75c) is replaced by <COOLAPK_APIKEY>.
import json, os, re, sys

out_dir = sys.argv[2]
plain, done = None, set()
for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
    m = re.match(r'COMPRESS@0x[0-9a-f]+ in\[\d+\]=([0-9a-f]+)', l)
    if m: plain = bytes.fromhex(m.group(1)).decode('utf-8', 'surrogateescape'); continue
    m = re.match(r'NET URL "https://[^/]+/a/(\w+)/', l)
    if m and plain and m.group(1) not in done:
        d = json.loads(plain)
        if '75c' in d: d['75c'] = '<COOLAPK_APIKEY>'
        with open(os.path.join(out_dir, f'payload_{m.group(1)}.json'), 'w', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(d, ensure_ascii=False, indent=1) + '\n')
        done.add(m.group(1)); plain = None
print('wrote', ' '.join(sorted(done)))
