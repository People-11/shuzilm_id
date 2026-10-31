# Call one libdu function under unicorn with Python stubs for libc and for chosen internal functions.
# Reads sample/libdu.so (env LIBDU overrides).
# import ucall; u = ucall.U(); u.stub(0x4adb4, lambda u: u.cstr_new("02:11:22:33:44:55")); u.call(0x4afb4, 1, 2)
import re, struct, sys
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

import os
_HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.environ.get('LIBDU', os.path.join(_HERE, '..', '..', 'sample', 'libdu.so'))
sys.path.insert(0, _HERE)
import elf
BASE, IMG = 0, 0x200000
STUBS, HEAP, STACK, TLS = 0x10000000, 0x20000000, 0x30000000, 0x40000000

class U:
    def __init__(s):
        s.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        data = open(SO, 'rb').read()
        s.uc.mem_map(BASE, IMG)
        # load PT_LOAD segments
        phoff, = struct.unpack_from('<Q', data, 0x20); phnum, = struct.unpack_from('<H', data, 0x38)
        for i in range(phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', data, phoff + i * 56)
            if t == 1: s.uc.mem_write(va, data[off:off + fsz])
        for slot, target in elf.relative(data).items(): s.uc.mem_write(slot, struct.pack('<Q', target))
        for slot, (value, _) in elf.globdat(data).items():
            if value: s.uc.mem_write(slot, struct.pack('<Q', value))
        s.plt = elf.plt(data)
        s.uc.mem_map(STUBS, 0x100000); s.uc.mem_map(HEAP, 0x1000000); s.uc.mem_map(STACK, 0x100000); s.uc.mem_map(TLS, 0x1000)
        s.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
        s.heap = HEAP; s.handlers = {}; s.trace = []
        s.uc.mem_write(STUBS, b'\xc0\x03\x5f\xd6' * (0x100000 // 4))  # ret everywhere
        for k, (slot, name) in enumerate(sorted(s.plt.items())):
            a = STUBS + 0x1000 + k * 4
            s.uc.mem_write(slot, struct.pack('<Q', a)); s.handlers[a] = ('libc', name)
        s.uc.hook_add(UC_HOOK_CODE, s._hook, begin=STUBS, end=STUBS + 0x100000)
        s.internal = {}
        s.uc.hook_add(UC_HOOK_CODE, s._ihook, begin=BASE, end=IMG)
        s.ihit = set(); s.lenient = False; s.log = []

    def stub(s, addr, fn): s.internal[addr] = fn
    def r(s, i): return s.uc.reg_read(UC_ARM64_REG_X0 + i) if i < 29 else None
    def ret(s, v):
        s.uc.reg_write(UC_ARM64_REG_X0, v & 0xffffffffffffffff)
        s.uc.reg_write(UC_ARM64_REG_PC, s.uc.reg_read(UC_ARM64_REG_LR))
    def malloc(s, n):
        a = (s.heap + 15) & ~15; s.heap = a + max(n, 1); s.uc.mem_write(a, b'\0' * max(n, 1)); return a
    def cstr(s, a):
        out = b''
        while True:
            c = s.uc.mem_read(a + len(out), 64); i = c.find(b'\0')
            if i >= 0: return (out + c[:i]).decode('latin1')
            out += c
    def cstr_new(s, t):
        if t is None: return 0
        b = t.encode('latin1') + b'\0'; a = s.malloc(len(b)); s.uc.mem_write(a, b); return a

    def _ihook(s, uc, addr, size, _):
        fn = s.internal.get(addr)
        if fn is not None:
            v = fn(s); s.trace.append((hex(addr), v)); s.ret(v if isinstance(v, int) else 0)

    def _hook(s, uc, addr, size, _):
        h = s.handlers.get(addr)
        if not h: return
        name = h[1]; r = s.r
        if name in ('malloc',): return s.ret(s.malloc(r(0)))
        if name in ('free', 'pthread_mutex_lock', 'pthread_mutex_unlock'): return s.ret(0)
        if name in ('strlen', '__strlen_chk'): return s.ret(len(s.cstr(r(0))))
        if name in ('memcpy', '__memcpy_chk', 'memmove'):
            uc.mem_write(r(0), bytes(uc.mem_read(r(1), r(2)))); return s.ret(r(0))
        if name in ('memset', '__memset_chk'): uc.mem_write(r(0), bytes([r(1) & 0xff]) * r(2)); return s.ret(r(0))
        if name == 'strcmp':
            a, b = s.cstr(r(0)), s.cstr(r(1)); return s.ret((a > b) - (a < b))
        if name == 'memcmp':
            a, b = bytes(uc.mem_read(r(0), r(2))), bytes(uc.mem_read(r(1), r(2))); return s.ret((a > b) - (a < b))
        if name in ('strcpy', '__strcpy_chk'):
            t = s.cstr(r(1)).encode('latin1') + b'\0'; uc.mem_write(r(0), t); return s.ret(r(0))
        if name in ('strcat', '__strcat_chk'):
            t = (s.cstr(r(0)) + s.cstr(r(1))).encode('latin1') + b'\0'; uc.mem_write(r(0), t); return s.ret(r(0))
        if name == 'strdup': return s.ret(s.cstr_new(s.cstr(r(0))))
        if name == '__stack_chk_fail': raise RuntimeError('stack_chk_fail')
        if s.lenient:  # log the call with any string-looking args, return -1 / 0
            args = []
            for k in range(4):
                v = r(k)
                try:
                    t = s.cstr(v) if v > 0x10000 else None
                except Exception: t = None
                args.append(repr(t) if t and t.isprintable() and len(t) > 1 else hex(v))
            s.log.append(f'{name}({", ".join(args)})')
            return s.ret(0 if name in ('fopen', 'popen', 'opendir') else -1 & 0xffffffffffffffff if name in ('access', 'open', '__open_2', 'stat', 'lstat') else 0)
        raise RuntimeError(f'unhandled libc {name}')

    def call(s, fn, *args, limit=5_000_000):
        sp = STACK + 0x100000 - 0x1000
        s.uc.reg_write(UC_ARM64_REG_SP, sp)
        for i, a in enumerate(args): s.uc.reg_write(UC_ARM64_REG_X0 + i, a)
        s.uc.reg_write(UC_ARM64_REG_LR, STUBS)  # returning here stops
        s.uc.emu_start(fn, STUBS, count=limit)
        return s.uc.reg_read(UC_ARM64_REG_X0)
