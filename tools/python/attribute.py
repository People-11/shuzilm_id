# usage: attribute.py trace.log > keys_runtime.tsv
# Runtime evidence for every payload key of a harness run: for each JSONObject.put the SDK makes, the value, the
# value decoded with that query's encoding parameter P (from its 2cO, see duenc.py), the libdu functions entered
# and the observable reads (JNI calls, field reads, properties, opened files, syscalls) between the previous put
# and this one, which is where the value came from. Keys libdu only ever puts raw (per keys_sources.py) are not
# decoded. The collectors column needs a run made with FNTRACE=<file from "elf.py libdu.so funcs">. One row per
# (query, key, value). Columns:
#   query  key  mode  value  decoded  collectors  reads   (mode: enc / raw per keys_sources.py, ? = no static site)
import collections, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import duenc

PUT = re.compile(r'^CALL org/json/JSONObject->put\(Ljava/lang/String;[^)]*\)\S* on .*? args=\["([^"]*)", (.*), \] => ')
NOISE = ('JSONObject', 'MessageDigest', 'String->getBytes', 'String-><init>', 'DeleteLocalRef', 'StringBuilder')
HELPER_CALLS = 300  # functions entered more often than this in the run are shared helpers, not collectors


def scan(path):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    fn_count = collections.Counter(l.split()[1] for l in lines if l.startswith('FN '))
    query, p, window, fns, out, seen = '0', 0, [], [], [], set()
    for l in lines:
        if l.startswith('==== QUERY'):
            query = l.split()[2]; window, fns = [], []
            continue
        m = PUT.match(l)
        if m:
            key, val = m.group(1), m.group(2)
            if key == '2cO' and val.startswith('"'): p = duenc.p_of(val.strip('"'))
            row = (query, key, val)
            if row not in seen:
                seen.add(row)
                out.append((query, key, val, p, list(fns), list(window)))
            window, fns = [], []
            continue
        if l.startswith('FN '):
            f = l.split()[1]
            if fn_count[f] <= HELPER_CALLS and f not in fns: fns.append(f)
        elif l.startswith(('CALL', 'GET', 'PROP', 'SYSCALL', 'THROW')) and not any(n in l for n in NOISE):
            window.append(re.sub(r' on [^ ]+\{[^}]{0,120}\}', '', l)[:160])
    return out


def decoded(val, p):
    if not (val.startswith('"') and val.endswith('"')) or len(val) < 4: return ''
    try: s = val[1:-1].encode('latin1', 'backslashreplace').decode('unicode_escape')
    except Exception: return ''
    d = duenc.dec(s, p)
    return d if d != s and all(32 <= ord(c) < 127 for c in d) else ''


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    import elf, keys_sources
    modes = collections.defaultdict(set)  # key -> {"enc", "raw"} from the static put modes
    data = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'sample', 'libdu.so'), 'rb').read()
    for r in keys_sources.rows(data, elf.relative(data), elf.funcs(data)):
        modes[r[0]].add('enc' if re.match(r'putMode\((2|3|0xa)\)', r[3]) else 'raw')
    print('query\tkey\tmode\tvalue\tdecoded\tcollectors\treads')
    for q, k, v, p, fns, reads in scan(sys.argv[1]):
        mode = '/'.join(sorted(modes[k])) or '?'  # "?" = no static put site for the key (shared or computed)
        d = decoded(v, p) if mode != 'raw' else ''
        print('\t'.join([q, k, mode, v[:100], d[:100], ' '.join('sub_' + f[2:] for f in fns[:6]),
                         ' || '.join(r for r in reads[-12:])]))
