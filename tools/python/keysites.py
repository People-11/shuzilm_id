# usage: keysites.py <libdu.so> <relocs.txt> <funcs.txt>  -> every site that loads an encrypted-string GOT slot, with the
# decoded string, the enclosing function, and the next put-helper call after it
import sys, re, bisect
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
data = open(sys.argv[1], 'rb').read()
got = {}
for line in open(sys.argv[2]):
    m = re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_RELATIVE\s+([0-9a-f]+)', line)
    if m: got[int(m.group(1), 16)] = int(m.group(2), 16)
funcs = sorted(int(l, 16) for l in open(sys.argv[3]) if l.strip())
TEXT, TEXT_END = 0x3d6c4, 0x3d6c4 + 0x115308

def dec(a):
    out = []; k = 0
    while a + 2*k + 1 < len(data) and data[a + 2*k + 1] and k < 200:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    return bytes(out)

strs = {}
for slot, tgt in got.items():
    if 0x157700 <= slot < 0x1583b0 and tgt < len(data):
        s = dec(tgt)
        if s and all(32 <= c < 127 for c in s): strs[slot] = s.decode()

PUTS = {0xf07fc: 'putMode', 0xf0378: 'putStr', 0xf220c: 'putInt', 0xf2160: 'putObj'}
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
regs = {}
pending = []  # (pc, str) awaiting a put call
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

for a, s, put in out:
    f = funcs[bisect.bisect_right(funcs, a) - 1] if funcs else 0
    p = f'{put[1]}@{put[0]:#x}' if put else ''
    print(f'{a:#x}\tsub_{f:x}\t{s!r}\t{p}')
