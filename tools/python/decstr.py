# usage: decstr.py <so> <decfn_hex> <text_off_hex> <text_size_hex> <relocs.txt from readelf -rW>
import sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
data = open(sys.argv[1], 'rb').read()
DEC = int(sys.argv[2], 16)
TEXT_OFF, TEXT_SZ = int(sys.argv[3], 16), int(sys.argv[4], 16)
got = {}
for line in open(sys.argv[5]):
    m = re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_RELATIVE\s+([0-9a-f]+)', line)
    if m: got[int(m.group(1), 16)] = int(m.group(2), 16)

def dec(a):
    out = []; k = 0
    while data[a + 2*k + 1]:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    return bytes(out)

# self-check of the decoder on a synthetic blob: "Hi" -> bytes (('H'^0)+1, ('i'^1)+1)
_d = data; data = bytes([0, ord('H')+1, 0, (ord('i')^1)+1, 0, 0]); assert dec(0) == b'Hi'; data = _d

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
regs, seen = {}, {}
def insns():
    pc = TEXT_OFF
    while pc < TEXT_OFF + TEXT_SZ:
        last = None
        for last in md.disasm(data[pc:TEXT_OFF+TEXT_SZ], pc):
            yield last
        pc = (last.address + 4) if last else pc + 4  # skip undecodable word (embedded data)
        if last: pc += 0
        else: regs.clear()
for ins in insns():
    m, ops = ins.mnemonic, [o.strip() for o in ins.op_str.split(',')]
    if m == 'adrp':
        regs[ops[0]] = int(ops[1].lstrip('#'), 16)
    elif m == 'add' and len(ops) == 3 and ops[2].startswith('#') and ops[1] in regs:
        regs[ops[0]] = regs[ops[1]] + int(ops[2].lstrip('#'), 16)
    elif m == 'ldr' and len(ops) == 3 and ops[1].lstrip('[') in regs and ops[2].startswith('#'):
        slot = regs[ops[1].lstrip('[')] + int(ops[2].rstrip(']').lstrip('#'), 16)
        if slot in got: regs[ops[0]] = got[slot]
        else: regs.pop(ops[0], None)
    elif m == 'and' and ops[0] == 'x0' and ops[1] in regs:
        regs['x0'] = regs[ops[1]] & ~3
    elif m == 'mov' and len(ops) == 2 and ops[1] in regs:
        regs[ops[0]] = regs[ops[1]]
    elif m == 'bl':
        if int(ops[0].lstrip('#'), 16) == DEC and 'x0' in regs:
            seen.setdefault(regs['x0'], []).append(ins.address)
        for r in ('x0','x1','x2','x3','x4','x5','x6','x7','x8'): regs.pop(r, None)
for a in sorted(seen):
    try: s = dec(a)
    except IndexError: continue
    print(f"{a:#x}\t{','.join(hex(x) for x in seen[a])}\t{ascii(s.decode('latin1'))}")
