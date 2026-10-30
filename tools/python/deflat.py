# usage: deflat.py <libdu.so> <relocs.txt> <func_hex> <end_hex> <state_reg> <dispatch_hex,...> [--dot]
# Recovers the state machine of an OLLVM-flattened function. Each state value is walked through the dispatcher's
# compare tree by a small interpreter (constants in w/x registers, flags from cmp/tst), then on into its handler until
# control comes back to a dispatcher entry; the state register there is the successor. Unknown conditions fork, and
# the fork records what it depended on (a call result, a stack slot). OLLVM's bogus predicates read two globals
# (x*(x-1) even || y < 10); those loads are taken as 0, which makes them pick the real edge.
import sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

data = open(sys.argv[1], 'rb').read()
got = {}
for line in open(sys.argv[2]):
    m = re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_RELATIVE\s+([0-9a-f]+)', line)
    if m: got[int(m.group(1), 16)] = int(m.group(2), 16)
    m = re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_GLOB_DAT\s+([0-9a-f]+) (x|y)(\.\d+)? ', line)
    if m: got[int(m.group(1), 16)] = int(m.group(2), 16)  # OLLVM's opaque-predicate globals
FUNC, END = int(sys.argv[3], 16), int(sys.argv[4], 16)
SREG = sys.argv[5]
if sys.argv[6] == 'auto':
    # dispatcher = the most frequent target of unconditional branches; state reg = what it compares first
    import collections
    _md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cnt = collections.Counter(); pc = FUNC
    while pc < END:
        n = 0
        for i in _md.disasm(data[pc:END], pc):
            n += 1; pc = i.address + 4
            if i.mnemonic == 'b': cnt[int(i.op_str.lstrip('#'), 16)] += 1
        if n == 0: pc += 4
    tgt = cnt.most_common(1)[0][0]
    for i in _md.disasm(data[tgt:tgt + 64], tgt):
        if i.mnemonic == 'cmp':
            r = i.op_str.split(',')[0].strip(); SREG = 'x' + r[1:]; break
    DISPATCH = {tgt}
    print(f'# auto dispatcher {tgt:#x} state {SREG}')
else:
    DISPATCH = {int(a, 16) for a in sys.argv[6].split(',')}
DEC = 0x1143bc
NAMES = {0xf07fc: 'putMode', 0xf0378: 'putStr', 0xf220c: 'putInt', 0xf2160: 'putObj', 0xdc4cc: 'free', DEC: 'dec',
         0xf7cd8: 'callObj', 0xf5088: 'jstr2c', 0xf5348: 'delLocal', 0xf3274: 'prefGet', 0xedbfc: 'noPerm',
         0x13fe10: 'sdkInt', 0xf53f0: 'newStr'}
M32 = 0xffffffff

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
FP = None  # x29 = final sp + FP
_pro = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(data[FUNC:FUNC + 160], FUNC))
for _a, _b in zip(_pro, _pro[1:]):
    if _a.mnemonic == 'mov' and _a.op_str == 'x29, sp' and _b.mnemonic == 'sub' and _b.op_str.startswith('sp, sp, #'):
        _m = re.match(r'sp, sp, #(\w+)(?:, lsl #(\d+))?', _b.op_str); FP = int(_m.group(1), 0) << int(_m.group(2) or 0); break
    if _a.mnemonic == 'add' and _a.op_str.startswith('x29, sp, #'):
        FP = int(_a.op_str.split('#')[1], 0); break
GSTORES = {}  # stack offset -> values stored there by any handler
cache = {}
def insn(a):
    if a not in cache:
        cache[a] = next(md.disasm(data[a:a + 4], a), None)
    return cache[a]

def dec(a):
    out = []; k = 0
    while a + 2*k + 1 < len(data) and data[a + 2*k + 1] and k < 300:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    s = bytes(out)
    return s.decode('latin1') if s and all(32 <= c < 127 for c in s) else None

def rn(r):  # canonical name: x0..x30, sp, zr
    r = md.reg_name(r)
    if r in ('wzr', 'xzr'): return 'zr'
    if r == 'wsp': return 'sp'
    return 'x' + r[1:] if r[0] == 'w' else r

def is32(r): return md.reg_name(r)[0] == 'w'

def spoff(mem):
    if not mem.base or mem.index: return None
    b = rn(mem.base)
    if b == 'sp': return mem.disp
    if b in ('x29', 'fp') and FP is not None: return FP + mem.disp
    return None

class St:
    def __init__(s, regs=None, flags=None, conds=None, mem=None):
        s.regs = dict(regs or {}); s.flags = flags; s.conds = list(conds or []); s.mem = dict(mem or {})
    def copy(s): return St(s.regs, s.flags, s.conds, s.mem)
    def get(s, r):
        if r == 'zr': return 0
        return s.regs.get(r)
    def set(s, r, v, w32=False):
        if r == 'zr': return
        if isinstance(v, int): v &= (M32 if w32 else (1 << 64) - 1)
        if v is None: s.regs.pop(r, None)
        else: s.regs[r] = v

def opval(st, op, w32):
    if op.type == ARM64_OP_IMM:
        v = op.imm
    elif op.type == ARM64_OP_REG:
        v = st.get(rn(op.reg))
        if isinstance(v, int) and w32: v &= M32
    else: return None
    if isinstance(v, int) and op.shift.type and op.shift.value:
        t, n = op.shift.type, op.shift.value
        v = (v << n) if t == 1 else (v >> n) if t == 2 else None
    return v

def cond_eval(cc, f):
    if f is None: return None
    n, z, c, v = f
    return {'eq': z, 'ne': not z, 'hs': c, 'cs': c, 'lo': not c, 'cc': not c, 'mi': n, 'pl': not n, 'vs': v, 'vc': not v,
            'hi': c and not z, 'ls': not c or z, 'ge': n == v, 'lt': n != v, 'gt': not z and n == v, 'le': z or n != v,
            'al': True}[cc]

def sub_flags(a, b, bits):
    m = (1 << bits) - 1; a &= m; b &= m
    r = (a - b) & m
    sa, sb, sr = a >> (bits - 1), b >> (bits - 1), r >> (bits - 1)
    return (sr == 1, r == 0, a >= b, (sa != sb) and (sr != sa))

CC = {1: 'eq', 2: 'ne', 3: 'hs', 4: 'lo', 5: 'mi', 6: 'pl', 7: 'vs', 8: 'vc', 9: 'hi', 10: 'ls', 11: 'ge', 12: 'lt',
      13: 'gt', 14: 'le', 15: 'al', 16: 'nv'}
def ccname(i):
    c = i.cc
    return CC.get(c, 'al')

def step(st, pc, events, desc):
    """Interpret one instruction; returns list of (state, next_pc) (2 on an unknown branch)."""
    i = insn(pc)
    if i is None: return []
    m, ops = i.mnemonic, i.operands
    nxt = pc + 4
    w32 = bool(ops) and ops[0].type == ARM64_OP_REG and is32(ops[0].reg)
    d = rn(ops[0].reg) if ops and ops[0].type == ARM64_OP_REG else None
    try:
        if m == 'mov' or m == 'movz':
            st.set(d, opval(st, ops[1], w32), w32)
        elif m in ('movn', 'mvn'):
            v = opval(st, ops[1], w32); st.set(d, ~v if isinstance(v, int) else None, w32)
        elif m == 'neg':
            v = opval(st, ops[1], w32); st.set(d, -v if isinstance(v, int) else None, w32)
        elif m in ('sxtw', 'uxtw', 'sxtb', 'uxtb', 'sxth', 'uxth'):
            v = opval(st, ops[1], True)
            if isinstance(v, int):
                b = {'w': 32, 'b': 8, 'h': 16}[m[-1]]; v &= (1 << b) - 1
                if m[0] == 's' and v >> (b - 1): v -= 1 << b
            st.set(d, v, w32)
        elif m == 'movk':
            old = st.get(d); imm = ops[1].imm; sh = ops[1].shift.value if ops[1].shift.type else 0
            st.set(d, (old & ~(0xffff << sh)) | (imm << sh) if isinstance(old, int) else None, w32)
        elif m == 'adrp':
            st.set(d, ops[1].imm)
        elif m in ('add', 'sub', 'eor', 'orr', 'and', 'mul', 'adds', 'subs', 'ands', 'lsl', 'lsr', 'asr', 'orn', 'bic', 'eon'):
            a = opval(st, ops[1], w32); b = opval(st, ops[2], w32) if len(ops) > 2 else None
            if m == 'and' and isinstance(st.regs.get(rn(ops[1].reg)) if ops[1].type == ARM64_OP_REG else None, (str, tuple)):
                st.set(d, st.regs.get(rn(ops[1].reg))); return [(st, nxt)]
            if isinstance(a, int) and isinstance(b, int):
                bits = 32 if w32 else 64; mk = (1 << bits) - 1
                r = {'add': a + b, 'adds': a + b, 'sub': a - b, 'subs': a - b, 'eor': a ^ b, 'orr': a | b, 'and': a & b,
                     'ands': a & b, 'mul': a * b, 'lsl': a << (b % bits), 'lsr': (a & mk) >> (b % bits),
                     'asr': ((a & mk) - ((a & mk) >> (bits - 1) << bits)) >> (b % bits), 'orn': a | ~b, 'bic': a & ~b,
                     'eon': a ^ ~b}[m]
                st.set(d, r, w32)
                if m in ('subs',): st.flags = sub_flags(a, b, bits)
                if m in ('ands',): r &= mk; st.flags = (r >> (bits - 1) == 1, r == 0, False, False)
                if m == 'adds': st.flags = None
            else:
                st.set(d, None)
                if m in ('subs', 'adds', 'ands'): st.flags = None; st.fdesc = f'{i.mnemonic} {i.op_str}@{pc:#x}'
        elif m in ('cmp', 'cmn', 'tst'):
            w32 = ops[0].type == ARM64_OP_REG and is32(ops[0].reg)
            a = opval(st, ops[0], w32); b = opval(st, ops[1], w32)
            bits = 32 if w32 else 64
            if isinstance(a, int) and isinstance(b, int):
                if m == 'cmp': st.flags = sub_flags(a, b, bits)
                elif m == 'cmn': st.flags = sub_flags(a, -b, bits)
                else:
                    r = a & b & ((1 << bits) - 1); st.flags = (r >> (bits - 1) == 1, r == 0, False, False)
            else:
                st.flags = None; st.fdesc = f'{i.mnemonic} {i.op_str} [{desc(st, ops[0])}]@{pc:#x}'
        elif m in ('csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm', 'cinc'):
            c = cond_eval(ccname(i), st.flags)
            if m == 'cset': a, b = 1, 0
            elif m == 'csetm': a, b = -1, 0
            elif m == 'cinc':
                v = opval(st, ops[1], w32); a, b = (v + 1 if isinstance(v, int) else None), v
            else:
                a = opval(st, ops[1], w32); b = opval(st, ops[2], w32)
                if m == 'csinc' and isinstance(b, int): b += 1
                if m == 'csinv' and isinstance(b, int): b = ~b
                if m == 'csneg' and isinstance(b, int): b = -b
            if c is None and m in ('cset', 'csetm'):
                st.set(d, f'<{getattr(st, "fdesc", "?")} {ccname(i)}>'); return [(st, nxt)]
            if c is None:
                s2 = st.copy()
                why = getattr(st, 'fdesc', '?')
                st.set(d, a, w32); st.conds.append(f'{why} {ccname(i)}')
                s2.set(d, b, w32); s2.conds.append(f'{why} !{ccname(i)}'); s2.fdesc = why; s2.flags = None
                return [(st, nxt), (s2, nxt)]
            st.set(d, a if c else b, w32)
        elif m in ('ldr', 'ldur', 'ldrb', 'ldrsw', 'ldrh', 'ldrsb', 'ldurb', 'ldursw', 'ldurh', 'ldursb', 'ldrsh', 'ldursh'):
            mem = ops[1].mem
            base = rn(mem.base) if mem.base else None
            bv = st.regs.get(base)
            so = spoff(mem)
            if so is not None:
                v = st.mem.get(so)
                st.set(d, v if v is not None else f'[sp+{so:#x}]')
            elif isinstance(bv, int) and m == 'ldr' and not mem.index:
                slot = bv + mem.disp
                if slot in got:
                    t = got[slot]
                    st.set(d, ('gotp', t))
                else: st.set(d, None)
            elif isinstance(bv, tuple) and bv[0] == 'gotp':
                t = bv[1] + mem.disp
                s = dec(t) if t < 0x157000 else None
                st.set(d, ('str', s) if s else 0)  # data globals: OLLVM opaque x / y -> 0
            else:
                st.set(d, None)
            if m == 'ldr' and len(ops) > 2: pass
        elif m == 'ldp':
            st.set(rn(ops[0].reg), None); st.set(rn(ops[1].reg), None)
            so = spoff(ops[2].mem)
            if so is not None:
                sz = 4 if is32(ops[0].reg) else 8
                for k in range(2):
                    v = st.mem.get(so + k * sz)
                    st.set(rn(ops[k].reg), v if v is not None else f'[sp+{so + k * sz:#x}]')
        elif m in ('str', 'stur', 'stp', 'strb', 'sturb', 'strh', 'sturh') and ops[-1].type == ARM64_OP_MEM and spoff(ops[-1].mem) is not None:
            off = spoff(ops[-1].mem); sz = 4 if is32(ops[0].reg) else 8
            for k, o in enumerate(ops[:-1]):
                v = st.get(rn(o.reg))
                if isinstance(v, int) and sz == 4: v &= M32
                if isinstance(v, int) and m.endswith('b'): v &= 0xff
                if v is None: st.mem.pop(off + k * sz, None)
                else: st.mem[off + k * sz] = v
                if pc not in PROLOGUE: GSTORES.setdefault(off + k * sz, set()).add(v if v is not None and not isinstance(v, tuple) or isinstance(v, tuple) else '?')
        elif m.startswith('st'):
            pass
        elif m == 'bl' or m == 'blr':
            t = ops[0].imm if m == 'bl' else None
            args = [st.get(f'x{k}') for k in range(5)]
            if t == DEC:
                a0 = args[0]
                s = None
                if isinstance(a0, tuple): s = dec(a0[1] & ~3)
                elif isinstance(a0, int): s = dec(a0)
                for k in range(19): st.set(f'x{k}', None)
                st.set('x0', ('str', s) if s else f'dec({a0})')
            else:
                events.append((pc, t, [fmt(a) for a in args]))
                for k in range(19): st.set(f'x{k}', None)
                st.set('x0', f'ret:{NAMES.get(t, "sub_%x" % t) if t else "blr"}@{pc:#x}')
            st.flags = None
        elif m == 'b':
            return [(st, ops[0].imm)]
        elif m.startswith('b.'):
            c = cond_eval(m[2:], st.flags)
            if c is None:
                s2 = st.copy(); why = getattr(st, 'fdesc', '?')
                st.conds.append(f'{why} {m[2:]}'); s2.conds.append(f'{why} !{m[2:]}'); s2.fdesc = why
                return [(st, ops[0].imm), (s2, nxt)]
            return [(st, ops[0].imm if c else nxt)]
        elif m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            v = opval(st, ops[0], w32)
            tgt = ops[-1].imm
            if isinstance(v, int):
                z = (v == 0) if m in ('cbz', 'cbnz') else ((v >> ops[1].imm) & 1) == 0
                take = z if m in ('cbz', 'tbz') else not z
                return [(st, tgt if take else nxt)]
            s2 = st.copy(); what = f'{m} {desc(st, ops[0])}@{pc:#x}'
            st.conds.append(what + ' taken'); s2.conds.append(what + ' not')
            return [(st, tgt), (s2, nxt)]
        elif m == 'ret' or m == 'br':
            return [(st, None)]
        else:
            if d: st.set(d, None)
    except Exception as e:
        if d: st.set(d, None)
    return [(st, nxt)]

def fmt(v):
    if isinstance(v, tuple):
        if v[0] == 'str': return repr(v[1])
        if v[0] == 'gotp':
            s = dec(v[1] & ~3); return repr(s) if s else f'got->{v[1]:#x}'
    if isinstance(v, int): return hex(v) if v > 9 or v < 0 else str(v)
    return str(v) if v is not None else '?'

def desc(st, op):
    if op.type == ARM64_OP_REG:
        v = st.get(rn(op.reg)); return fmt(v)
    return '?'

def walk(st, pc, limit=4000):
    """Run until a dispatcher entry is reached; returns list of (succ_state or None, conds, events)."""
    out = []
    work = [(st, pc, [], 0, frozenset())]
    while work:
        s, p, ev, n, seen = work.pop()
        if p is None:
            out.append(('RET', s.conds, ev)); continue
        if n > 0 and p in DISPATCH:
            v = s.get(SREG); out.append((v if isinstance(v, int) else fmt(v), s.conds, ev)); continue
        if n > limit or len(out) > 64: out.append(('LIMIT', s.conds, ev)); continue
        if (p, n > 0) in seen and n > 0 and p < FUNC: pass
        evs = list(ev)
        res = step(s, p, evs, desc)
        for s2, p2 in res:
            if p2 is not None and not (FUNC <= p2 < END):
                out.append((f'OUT:{p2:#x}', s2.conds, evs)); continue
            work.append((s2, p2, evs if len(res) == 1 else list(evs), n + 1, seen))
    return out

# prologue: from function start up to the first dispatcher entry
init = St()
res = walk(init, FUNC)
# keep the register environment at the dispatcher (callee-saved constants)
INIT = {}
for a in sys.argv[7:]:
    if a.startswith('--set='):
        for kv in a[6:].split(','):
            k, v = kv.split('='); INIT[k] = int(v, 0)
def env_at_dispatch():
    s = St(INIT); p = FUNC; ev = []
    for _ in range(5000):
        PROLOGUE.add(p)
        if p in DISPATCH: return s
        r = step(s, p, ev, desc)
        s, p = r[0]
    return s
PROLOGUE = set()
base = env_at_dispatch()
start = base.get(SREG)
print(f'# start state {fmt(start)}  env {{{", ".join(f"{k}={fmt(v)}" for k, v in base.regs.items() if isinstance(v, int) and k not in ("x0",))}}}')

def handler(K):
    s = base.copy(); s.set(SREG, K, True); s.conds = []; s.flags = None
    entry = min(DISPATCH)
    # enter via the dispatcher entry the state register is compared at
    return walk(s, sorted(DISPATCH)[0])

def build():
    graph = {}
    todo = [start]
    while todo:
        K = todo.pop()
        if not isinstance(K, int) or K in graph: continue
        r = handler(K)
        graph[K] = r
        for succ, conds, ev in r:
            if isinstance(succ, int) and succ not in graph: todo.append(succ)
    return graph
graph = build()
# pass 2: a stack slot that only one handler value is ever stored to (a flag, a decoded key) is known everywhere
for off, vs in GSTORES.items():
    if len(vs) == 1:
        v = next(iter(vs))
        if isinstance(v, str) and v != '?' and not v.startswith('[sp+'): base.mem.setdefault(off, v)
GSTORES.clear()
graph = build()

def evtxt(ev):
    out = []
    for pc, t, args in ev:
        nm = NAMES.get(t, f'sub_{t:x}' if t else 'blr')
        if nm in ('free', 'delLocal'): continue
        out.append(f'{nm}({", ".join(args[:5])})@{pc:#x}')
    return '; '.join(out)

for K in sorted(graph, key=lambda k: k & M32):
    r = graph[K]
    print(f'S{K & M32:08x}:')
    seen_l = set()
    for succ, conds, ev in r:
        sc = f'S{succ & M32:08x}' if isinstance(succ, int) else str(succ)
        c = (' if ' + ' & '.join(conds)) if conds else ''
        e = evtxt(ev)
        if (sc, c, e) in seen_l: continue
        seen_l.add((sc, c, e))
        print(f'   -> {sc}{c}' + (f'   [{e}]' if e else ''))
