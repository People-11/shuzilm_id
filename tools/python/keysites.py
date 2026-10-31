# usage: keysites.py <libdu.so>  -> every site that loads an encrypted-string GOT slot, with the
# decoded string, the enclosing function, and the next put-helper call after it
# As a module: keysites.key_loads(data, got) -> [(load_pc, string, (put_pc, put_name) or None)]
import sys, re, bisect
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
TEXT, TEXT_END = 0x3d6c4, 0x3d6c4 + 0x115308
PUTS = {0xf07fc: 'putMode', 0xf0378: 'putStr', 0xf220c: 'putInt', 0xf2160: 'putObj'}


def dec(data, a):
    out = []; k = 0
    while a + 2*k + 1 < len(data) and data[a + 2*k + 1] and k < 200:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    return bytes(out)


def key_loads(data, got):
    strs = {}
    for slot, tgt in got.items():
        if 0x157700 <= slot < 0x1583b0 and tgt < len(data):
            s = dec(data, tgt)
            if s and all(32 <= c < 127 for c in s): strs[slot] = s.decode()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    regs = {}
    pending = []  # indexes into out awaiting a put call
    out = []
    pc = TEXT
    while pc < TEXT_END:
        n = 0
        for ins in md.disasm(data[pc:TEXT_END], pc):
            n += 1
            m, ops = ins.mnemonic, [o.strip() for o in ins.op_str.split(',')]
            if m == 'adrp':
                regs[ops[0]] = int(ops[1].lstrip('#'), 16)
            elif m == 'ldr' and len(ops) >= 2 and ops[1].startswith('['):
                mm = re.match(r'\[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]$', ', '.join(ops[1:]))
                if mm and mm.group(1) in regs:
                    slot = regs[mm.group(1)] + int(mm.group(2) or '0', 0)
                    if slot in strs:
                        out.append([ins.address, strs[slot], None])
                        pending.append(len(out) - 1)
            elif m == 'bl':
                t = int(ops[0].lstrip('#'), 16)
                if t in PUTS:
                    for i in pending:
                        if ins.address - out[i][0] < 0x200: out[i][2] = (ins.address, PUTS[t])
                    pending = []
            if m in ('ret',): regs.clear(); pending = []
            pc = ins.address + 4
        if n == 0: pc += 4
    return [tuple(o) for o in out]


if __name__ == '__main__':
    import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import elf
    data = open(sys.argv[1], 'rb').read()
    funcs = elf.funcs(data)
    for a, s, put in key_loads(data, elf.relative(data)):
        f = funcs[bisect.bisect_right(funcs, a) - 1] if funcs else 0
        p = f'{put[1]}@{put[0]:#x}' if put else ''
        print(f'{a:#x}\tsub_{f:x}\t{s!r}\t{p}')
