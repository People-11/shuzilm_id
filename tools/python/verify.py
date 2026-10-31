# usage: verify.py [--claims docs/data/claims.tsv] [--no-harness] [--only ID,ID...]
# Checks every claim in claims.tsv against sample/libdu.so and prints PASS / FAIL per claim (exit 1 on any FAIL).
# Run from the repository root. Claim kinds (column "kind"):
#   static  key=K source=sub_X strings=a|b    a builder puts key K with a value returned by sub_X, whose decoded
#           [builder=sub_B]                   strings include a and b (keys_sources.py); with builder=, that builder
#   str     func=sub_X strings=a|b            sub_X decodes these strings (funcstr.py)
#   call    func=sub_X callee=sub_Y arg=s     sub_X calls sub_Y with an argument whose source mentions s (flow.py)
#   leaf    func=sub_X log=a|b                running sub_X alone under unicorn, its libc log contains a and b
#                                             (leafrun.py; this is where stack-XOR strings show up)
#   run     key=K expect=raw:V|dec:V|re:R|dre:R|absent   in a harness run with the claim's scenario, the first value
#                                             put under K (raw, or decoded with the run's P for dec / dre) is V,
#                                             matches R, or K is not put at all
#   read    text=a|b                          a harness run's trace contains a and b
#   mode    key=K expect=enc|raw              K's value changes (enc) / stays (raw) between 2cO ending 000 and 281
#   report  report=R keys=a|b                 the plaintext of report R (mdna, d2api, ...) in a harness run has keys a
#                                             and b, at any depth
# "scenario" is a JSON object of extra harness environment variables (FAKEFILE, INSTALLED, NATIVE, ...).
# Harness kinds need tools/harness built (mvn compile dependency:build-classpath -Dmdep.outputFile=cp.txt) and
# tools/harness/coolapk_cert.der; --no-harness skips them.
import json, os, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attribute, duenc, elf, flow, funcstr, keys_sources, leafrun

ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
HARNESS = os.path.join(ROOT, 'tools', 'harness')
REPLY = '{"err":"0","n_a":"DU0000000000000000000000000000000000000000000000000000TEST","aid":"AID_TEST",' \
        '"o_a":"OA22222222222","cdd":"CDD_TEST","nctl":"1"}'
BASE = {'RICH': '1', 'PATCH_KEYCHECK': '1', 'A7': '60000', 'IDLE': '40', 'MAXRUN': '600', 'QUERIES': '1', 'RESP_JSON': REPLY}


def kv(s):
    out = {}
    for part in re.split(r'\s+(?=\w+=)', s.strip()):
        k, _, v = part.partition('=')
        out[k] = v
    return out


class Ctx:
    def __init__(s):
        s.data = open(os.path.join(ROOT, 'sample', 'libdu.so'), 'rb').read()
        s.got = elf.relative(s.data)
        s.funcs = elf.funcs(s.data)
        s._rows = s._strs = None
        s.runs = {}

    def rows(s):
        if s._rows is None: s._rows = list(keys_sources.rows(s.data, s.got, s.funcs))
        return s._rows

    def strs(s):
        if s._strs is None: s._strs = funcstr.strings_by_func(s.data, s.got, s.funcs)
        return s._strs

    def run(s, scenario):
        key = json.dumps(scenario, sort_keys=True)
        if key not in s.runs:
            env = {**os.environ, **BASE, **scenario}
            cp = os.pathsep.join([os.path.join(HARNESS, 'target', 'classes'), open(os.path.join(HARNESS, 'cp.txt')).read().strip()])
            subprocess.run(['java', '-cp', cp, 'du.Harness'], cwd=HARNESS, env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=900)
            trace = os.path.join(HARNESS, 'trace.log')
            first = {}
            for q, k, v, p, _, _ in attribute.scan(trace):
                first.setdefault(k, (v, p))
            s.runs[key] = (first, open(trace, encoding='utf-8', errors='replace').read())
        return s.runs[key]


def value_of(v, p, how):
    raw = v[1:-1] if v.startswith('"') and v.endswith('"') else v
    if how == 'dec':
        try: raw = raw.encode('latin1', 'backslashreplace').decode('unicode_escape')
        except Exception: pass
        return duenc.dec(raw, p)
    return raw


def check(ctx, kind, args, scenario):
    if kind == 'static':
        want = [x for x in args.get('strings', '').split('|') if x]
        hits = [r for r in ctx.rows() if r[0] == args['key'] and (not args.get('source') or args['source'] in r[4].split(','))
                and r[1] == args.get('builder', r[1])]
        if not hits: return False, f"no put of {args['key']} with value from {args.get('source')} in {args.get('builder', 'any builder')}"
        miss = [w for w in want if not any(w in r[5] for r in hits)]
        return not miss, f"{hits[0][1]} {hits[0][2]} {hits[0][3]}" + (f'; missing {miss}' if miss else '')
    if kind == 'str':
        have = ctx.strs().get(int(args['func'][4:], 16), [])
        miss = [w for w in args['strings'].split('|') if not any(w in h for h in have)]
        return not miss, 'missing ' + str(miss) if miss else f'{len(have)} strings'
    if kind == 'call':
        f = int(args['func'][4:], 16); end = ctx.funcs[ctx.funcs.index(f) + 1]
        callee = int(args['callee'][4:], 16)
        calls = [(pc, a) for pc, t, a in flow.analyze(ctx.data, ctx.got, f, end) if t == callee]
        ok = [pc for pc, a in calls if any(args['arg'] in str(x) for x in a)]
        return bool(ok), (f'at {ok[0]:#x}' if ok else f'{len(calls)} calls, none with {args["arg"]!r}')
    if kind == 'leaf':
        log = ' ; '.join(leafrun.run(int(args['func'][4:], 16), dirents=[b'com.example.app']))
        miss = [w for w in args['log'].split('|') if w not in log]
        return not miss, 'missing ' + str(miss) if miss else 'all seen'
    if kind == 'run':
        first, _ = ctx.run(scenario)
        exp = args['expect']
        if exp == 'absent': return args['key'] not in first, 'absent' if args['key'] not in first else f'present: {first[args["key"]][0][:40]}'
        if args['key'] not in first: return False, 'key not put'
        v, p = first[args['key']]
        how, _, want = exp.partition(':')
        got = value_of(v, p, 'dec' if how in ('dec', 'dre') else 'raw')
        ok = re.search(want, got) is not None if how in ('re', 'dre') else got == want
        return ok, f'{got[:60]!r}'
    if kind == 'read':
        _, trace = ctx.run(scenario)
        miss = [w for w in args['text'].split('|') if w not in trace]
        return not miss, 'missing ' + str(miss) if miss else 'all seen'
    if kind == 'report':
        _, trace = ctx.run(scenario)
        have, plain = set(), None
        def walk(o):
            for k, v in o.items():
                have.add(k)
                if isinstance(v, dict): walk(v)
        for l in trace.split('\n'):
            m = re.match(r'COMPRESS@0x[0-9a-f]+ in\[\d+\]=([0-9a-f]+)', l)
            if m: plain = bytes.fromhex(m.group(1)).decode('utf-8', 'replace'); continue
            m = re.match(r'NET URL "https://[^/]+/a/(\w+)/', l)
            if m and plain:
                if m.group(1) == args['report']: walk(json.loads(plain))
                plain = None
        miss = [k for k in args['keys'].split('|') if k not in have]
        return not miss, 'missing ' + str(miss) if miss else f'all {len(args["keys"].split("|"))} in {args["report"]}'
    if kind == 'mode':
        a = ctx.run(dict(scenario, NS3='000'))[0].get(args['key'])
        b = ctx.run(dict(scenario, NS3='281'))[0].get(args['key'])
        if not a or not b: return False, 'key not put'
        got = 'enc' if a[0] != b[0] else 'raw'
        return got == args['expect'], f'{a[0][:20]} / {b[0][:20]}'
    return False, f'unknown kind {kind}'


def main():
    argv = sys.argv[1:]
    path = os.path.join(ROOT, 'docs', 'data', 'claims.tsv')
    if '--claims' in argv: path = argv[argv.index('--claims') + 1]
    only = set(argv[argv.index('--only') + 1].split(',')) if '--only' in argv else None
    no_harness = '--no-harness' in argv
    if not no_harness:
        os.environ.setdefault('MSYS2_ENV_CONV_EXCL', '*')  # Git Bash would rewrite /paths inside FAKEFILE
    sys.stdout.reconfigure(encoding='utf-8')
    ctx, fails, n = Ctx(), 0, 0
    for line in open(path, encoding='utf-8'):
        if not line.strip() or line.startswith('#') or line.startswith('id\t'): continue
        cid, doc, kind, spec, scen, *_ = line.rstrip('\n').split('\t') + ['', '']
        if only and cid not in only: continue
        if no_harness and kind in ('run', 'read', 'mode', 'report'):
            print(f'SKIP {cid:6} {doc:8} {kind:6} {spec}'); continue
        try: ok, detail = check(ctx, kind, kv(spec), json.loads(scen) if scen.strip() else {})
        except Exception as e: ok, detail = False, f'{type(e).__name__}: {e}'
        n += 1; fails += not ok
        print(f'{"PASS" if ok else "FAIL"} {cid:6} {doc:8} {kind:6} {spec[:70]:70} {detail}')
    print(f'\n{n - fails}/{n} passed')
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
