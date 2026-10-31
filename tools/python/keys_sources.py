# usage: keys_sources.py <libdu.so> > keys_sources.tsv
# Static map of every payload key: for each function that calls one of libdu's JSON put helpers (a "builder"),
# flow.analyze() gives each put's key string, its value's source (the call whose result is put) and the encoding
# mode; the source function's decoded strings are joined in. Columns:
#   key  builder  put_pc  put(mode)  value_source  source_strings  note
# note "ambiguous: a|b|c" = the flattened builder reuses one stack slot for several keys, and "shared put site:
# a|b|c" = one put call serves several keys (the key is picked by the state machine); in both cases the static pass
# can't tell which key this put writes, so key is "?" (resolve those with a harness run: attribute.py).
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import elf, flow, funcstr, keysites

PUTS = {0xf07fc: 'putMode', 0xf0378: 'putStr', 0xf220c: 'putInt', 0xf2160: 'putObj'}


def builders(data, funcs):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for fi, f in enumerate(funcs[:-1]):
        end = funcs[fi + 1]
        if f in PUTS: continue
        for i in md.disasm(data[f:end], f):
            if i.mnemonic == 'bl' and int(i.op_str.lstrip('#'), 16) in PUTS:
                out.append((f, end)); break
    return out


def rows(data, got, funcs):
    strs = funcstr.strings_by_func(data, got, funcs)
    shared = {}
    for _, s, put in keysites.key_loads(data, got):
        if put and len(s) == 3: shared.setdefault(put[0], set()).add(s)
    for f, end in builders(data, funcs):
        for pc, t, args in flow.analyze(data, got, f, end):
            if t not in PUTS: continue
            args = ['' if x is None else str(x) for x in args]
            keys = sorted(set(re.findall(r'"([^"]*)"', args[1])))
            srcs = sorted(set(re.findall(r'ret:sub_([0-9a-f]+)@', args[2])), key=lambda s: int(s, 16))
            kind = PUTS[t]
            if kind == 'putMode':
                m = re.search(r'const:(\S+)', args[4])
                kind += f'({m.group(1)})' if m else '(?)'
            src_strs = ' ; '.join(f'sub_{s}: ' + ' | '.join(repr(x) for x in strs.get(int(s, 16), [])) for s in srcs)
            site = sorted(shared.get(pc, ()))
            key = keys[0] if len(keys) == 1 and len(site) <= 1 else '?'
            note = (f'ambiguous: {"|".join(keys)}' if len(keys) > 1 else
                    f'shared put site: {"|".join(site)}' if len(site) > 1 else '')
            yield key, f'sub_{f:x}', f'{pc:#x}', kind, ','.join(f'sub_{s}' for s in srcs), src_strs, note


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    data = open(sys.argv[1], 'rb').read()
    out = sorted(rows(data, elf.relative(data), elf.funcs(data)), key=lambda r: (r[0].lower(), r[0], int(r[2], 16)))
    print('key\tbuilder\tput_pc\tput\tvalue_source\tsource_strings\tnote')
    for r in out: print('\t'.join(r))
