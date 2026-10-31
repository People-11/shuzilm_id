# usage: funcstr.py <libdu.so> > funcstr.txt
# Every string each function decodes (sub_1143bc on an adrp+add address or a GOT slot); the stack-string
# XOR blocks are not covered. One line per function: "0xADDR<TAB>'s1' | 's2' ..."
# As a module: funcstr.strings_by_func(data, got, funcs) -> {func: [s1, s2, ...]}
import sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
DEC = 0x1143bc


def dec(data, a):
    out = []; k = 0
    while 0 < a < len(data) - 2 * k - 1 and data[a + 2 * k + 1] and k < 300:
        out.append(((data[a + 2 * k + 1] - 1) ^ k) & 0xff); k += 1
    s = bytes(out)
    try: t = s.decode('utf-8')
    except UnicodeDecodeError: return None
    return t if t and all(c.isprintable() or c in '\t\n' for c in t) else None


def strings_by_func(data, got, funcs):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    res = {}
    for fi, f in enumerate(funcs):
        end = funcs[fi + 1] if fi + 1 < len(funcs) else f + 4
        regs, strs, pc = {}, [], f
        while pc < end:
            n = 0
            for i in md.disasm(data[pc:end], pc):
                n += 1; pc = i.address + 4
                o = [x.strip() for x in i.op_str.split(',')]
                m = i.mnemonic
                try:
                    if m == 'adrp': regs[o[0]] = int(o[1][1:], 16)
                    elif m == 'add' and len(o) == 3 and o[1] in regs and o[2].startswith('#'): regs[o[0]] = regs[o[1]] + int(o[2][1:], 0)
                    elif m == 'ldr' and len(o) >= 2:
                        mm = re.match(r'\[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]$', ', '.join(o[1:]))
                        if mm and mm.group(1) in regs: regs[o[0]] = got.get(regs[mm.group(1)] + int(mm.group(2) or '0', 0), -1)
                        else: regs.pop(o[0], None)
                    elif m == 'and' and len(o) == 3 and o[1] in regs: regs[o[0]] = regs[o[1]] & ~3
                    elif m == 'bl':
                        if int(o[0][1:], 16) == DEC and 'x0' in regs:
                            s = dec(data, regs['x0'])
                            if s is not None and s not in strs: strs.append(s)
                        for r in [f'x{k}' for k in range(19)]: regs.pop(r, None)
                    elif o and re.match(r'[xw]\d+$', o[0]) and m not in ('cmp', 'tst', 'cmn', 'str', 'stp', 'strb', 'stur', 'sturb', 'strh'):
                        regs.pop('x' + o[0][1:], None)
                except (ValueError, IndexError):
                    pass
            if n == 0: pc += 4
        if strs: res[f] = strs
    return res


if __name__ == '__main__':
    import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.reconfigure(encoding="utf-8")
    import elf
    data = open(sys.argv[1], 'rb').read()
    for f, strs in strings_by_func(data, elf.relative(data), elf.funcs(data)).items():
        print(f'{f:#x}\t' + ' | '.join(repr(s) for s in strs))
