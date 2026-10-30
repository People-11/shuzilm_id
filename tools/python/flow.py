# usage: flow.py <libdu.so> <relocs.txt> <start_hex> <end_hex> [key...]
# Stack-slot dataflow over a control-flow-flattened function: what each sp slot is written from (a decoded key string,
# a call's result, a constant), then every call with its x0..x4 sources. Blocks are tiny, so register state is tracked
# linearly and dropped at branches; slot facts are global across the function (multi-pass until stable).
import sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
data = open(sys.argv[1], 'rb').read()
got = {}
for line in open(sys.argv[2]):
    m = re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_RELATIVE\s+([0-9a-f]+)', line)
    if m: got[int(m.group(1), 16)] = int(m.group(2), 16)
START, END = int(sys.argv[3], 16), int(sys.argv[4], 16)
DEC = 0x1143bc
NAMES = {0xf07fc: 'putMode', 0xf0378: 'putStr', 0xf220c: 'putInt', 0xf2160: 'putObj', 0xdc4cc: 'free', DEC: 'dec'}

def dec(a):
    out = []; k = 0
    while a + 2*k + 1 < len(data) and data[a + 2*k + 1] and k < 200:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    s = bytes(out)
    return s.decode('latin1') if s and all(32 <= c < 127 for c in s) else None

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
insns = []
pc = START
while pc < END:
    n = 0
    for i in md.disasm(data[pc:END], pc):
        insns.append(i); n += 1; pc = i.address + 4
    if n == 0: pc += 4

FP = 0
for a, b in zip(insns, insns[1:]):
    if a.mnemonic == 'mov' and a.op_str == 'x29, sp' and b.mnemonic == 'sub' and b.op_str.startswith('sp, sp, #'):
        FP = int(b.op_str.split('#')[1], 0); break
slots = {}   # sp offset -> set of values
def norm(r):
    return 'x' + r[1:] if r[0] == 'w' else r

def run():
    regs = {}; calls = []
    def val(r):
        r = norm(r)
        if r in ('xzr',): return 'const:0'
        return regs.get(r)
    def sval(off):
        v = slots.get(off)
        return '|'.join(sorted(v)) if v else f'sp+{off:#x}'
    changed = False
    def wslot(off, v):
        nonlocal changed
        if v is None: return
        s = slots.setdefault(off, set())
        if v not in s and len(s) < 6: s.add(v); changed = True
    for i in insns:
        opstr = re.sub(r'\[x29, #(-?0x[0-9a-f]+|-?\d+)\]', lambda mm: f'[sp, #{FP + int(mm.group(1), 0):#x}]', i.op_str) if FP else i.op_str
        m, ops = i.mnemonic, [o.strip() for o in opstr.split(',')]
        if m in ('ldur', 'stur'): m = m.replace('ur', 'r')
        try:
            if m == 'adrp': regs[norm(ops[0])] = ('page', int(ops[1].lstrip('#'), 16))
            elif m == 'add' and len(ops) == 3 and ops[2].startswith('#'):
                b = regs.get(norm(ops[1]))
                imm = int(ops[2].lstrip('#'), 0)
                if ops[1] == 'sp': regs[norm(ops[0])] = f'&sp+{imm:#x}'
                elif isinstance(b, tuple): regs[norm(ops[0])] = ('page', b[1] + imm)
                else: regs.pop(norm(ops[0]), None)
            elif m == 'ldr' and ops[1].startswith('[') and len(ops) <= 3:
                mm = re.match(r'\[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]!?$', ', '.join(ops[1:]))
                d = norm(ops[0])
                if not mm: regs.pop(d, None); continue
                base, off = mm.group(1), int(mm.group(2) or '0', 0)
                if base == 'sp': regs[d] = sval(off)
                elif isinstance(regs.get(norm(base)), tuple):
                    slot = regs[norm(base)][1] + off
                    t = got.get(slot)
                    s = dec(t) if t else None
                    regs[d] = f'"{s}"' if s else (f'got:{slot:#x}->{t:#x}' if t else f'mem:{slot:#x}')
                else: regs.pop(d, None)
            elif m == 'ldp' and ops[2].startswith('[sp'):
                mm = re.match(r'\[sp(?:, #(0x[0-9a-f]+|\d+))?\]$', ops[2])
                if mm:
                    off = int(mm.group(1) or '0', 0); sz = 8 if ops[0][0] == 'x' else 4
                    regs[norm(ops[0])] = sval(off); regs[norm(ops[1])] = sval(off + sz)
            elif m in ('str', 'strb', 'stur') and '[sp' in opstr:
                mm = re.search(r'\[sp(?:, #(0x[0-9a-f]+|\d+))?\]', opstr)
                if mm: wslot(int(mm.group(1) or '0', 0), val(ops[0]) or f'?{ops[0]}@{i.address:#x}')
            elif m == 'stp' and '[sp' in opstr:
                mm = re.search(r'\[sp(?:, #(0x[0-9a-f]+|\d+))?\]', opstr)
                if mm:
                    off = int(mm.group(1) or '0', 0); sz = 8 if ops[0][0] == 'x' else 4
                    wslot(off, val(ops[0]) or f'?{ops[0]}@{i.address:#x}'); wslot(off + sz, val(ops[1]) or f'?{ops[1]}@{i.address:#x}')
            elif m == 'and' and len(ops) == 3:
                regs[norm(ops[0])] = val(ops[1])
            elif m == 'mov' and len(ops) == 2:
                if ops[1].startswith('#'): regs[norm(ops[0])] = f'const:{ops[1][1:]}'
                elif ops[1] == 'sp': regs[norm(ops[0])] = '&sp+0x0'
                else: regs[norm(ops[0])] = val(ops[1])
            elif m in ('movz', 'movk', 'movn', 'orr', 'eor', 'sub', 'cmp', 'csel', 'cset', 'ldrb', 'ldrsw', 'ldur', 'ldrh', 'tst', 'ldp', 'lsl', 'lsr', 'mul', 'madd', 'neg', 'sxtw', 'uxtw', 'ubfx', 'sbfx'):
                if m == 'cset' or m == 'csel':
                    regs[norm(ops[0])] = f'cond@{i.address:#x}'
                elif m not in ('cmp', 'tst') and ops:
                    regs.pop(norm(ops[0]), None)
                    if m == 'ldp': regs.pop(norm(ops[1]), None)
            elif m == 'bl':
                t = int(ops[0].lstrip('#'), 16)
                args = [val(f'x{k}') for k in range(5)]
                calls.append((i.address, t, args))
                for k in range(19): regs.pop(f'x{k}', None)
                if t == DEC and args[0]:
                    a = args[0]
                    regs['x0'] = a if a.startswith('"') else f'dec({a})'
                else:
                    regs['x0'] = f'ret:{NAMES.get(t, "sub_%x" % t)}@{i.address:#x}'
            elif m in ('b', 'br', 'ret', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz') or m.startswith('b.'):
                regs = {k: v for k, v in regs.items() if isinstance(v, tuple)}  # keep adrp pages only
            else:
                if ops and re.match(r'[wx]\d+$', ops[0]): regs.pop(norm(ops[0]), None)
        except (ValueError, IndexError):
            if ops and re.match(r'[wx]\d+$', ops[0]): regs.pop(norm(ops[0]), None)
    return calls, changed

for _ in range(8):
    calls, changed = run()
    if not changed: break
keys = set(sys.argv[5:])
for a, t, args in calls:
    name = NAMES.get(t, f'sub_{t:x}')
    if name in ('free', 'dec'): continue
    line = f'{a:#x} {name}(' + ', '.join(str(x) for x in args) + ')'
    if not keys or any(k in line for k in keys): print(line)
