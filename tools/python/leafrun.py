# usage: leafrun.py func_hex... [--line TEXT]... [--dir NAME]... [--exists PATH]...
# Runs libdu collector functions under unicorn (ucall.py) and logs what they look at: every file / directory they
# open, the formats they snprintf paths from, the paths they access / stat, the needles they strstr / strcmp
# with, the commands they popen. That's how strings built on the stack by XOR (invisible to funcstr.py) show up.
# fgets returns the --line texts in turn (default: one dummy line), readdir returns the --dir names, access/stat
# succeed only for --exists paths; the SDK's JNI helpers return 0, other libc calls are logged and return 0 / -1.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ucall

JNI = [0xf7cd8, 0xf5088, 0xf5348, 0xf53f0, 0xf7ed4, 0xf7dd8, 0xf83c8, 0xf8550, 0xf8668, 0xf78d8, 0xf77d8, 0xf76a8,
       0xf55d8, 0xf5634, 0xf5830, 0xf59a8, 0xf6004, 0xf6448, 0xf5f20, 0xf5c28, 0xf3274, 0xf367c, 0xf34ec, 0xe9e70,
       0x13fe10, 0xedbfc, 0xf02ac, 0xf07fc, 0xf0378, 0xf220c, 0xf2160]
QUIET = ('pthread_self', 'pthread_mutex_lock', 'pthread_mutex_unlock', 'free', 'malloc', 'calloc')


def run(fn, lines=(b'x\n',), dirents=(), exists=()):
    class V(ucall.U):
        def _hook(s, uc, addr, size, _):
            h = s.handlers.get(addr)
            if not h: return
            r, name = s.r, h[1]
            if name in ('fopen', 'open', '__open_2', 'opendir', 'popen'):
                s.log.append(f'{name}({s.cstr(r(0))!r})')
                return s.ret(0x6000 if name == 'opendir' else 3 if name in ('open', '__open_2') else 0x5000)
            if name == 'fgets':
                if s.i >= len(lines): return s.ret(0)
                uc.mem_write(r(0), lines[s.i] + bytes(1)); s.i += 1; return s.ret(r(0))
            if name == 'feof': return s.ret(1 if s.i >= len(lines) else 0)
            if name in ('fclose', 'closedir', 'pclose', 'close'): return s.ret(0)
            if name == 'readdir':
                if s.j >= len(dirents): return s.ret(0)
                d = s.malloc(280); uc.mem_write(d + 18, b'\x04' + dirents[s.j] + bytes(1)); s.j += 1; return s.ret(d)
            if name in ('strstr', 'strcasestr', 'strcmp', 'strncmp', 'strcasecmp'):
                a, b = s.cstr(r(0)), s.cstr(r(1))
                s.log.append(f'{name}({b!r})')
                if name in ('strstr', 'strcasestr'):
                    i = a.lower().find(b.lower()) if name == 'strcasestr' else a.find(b)
                    return s.ret(r(0) + i if i >= 0 else 0)
                if name == 'strncmp': a, b = a[:r(2)], b[:r(2)]
                if name == 'strcasecmp': a, b = a.lower(), b.lower()
                return s.ret((a > b) - (a < b))
            if name in ('__vsnprintf_chk', '__sprintf_chk', 'snprintf', '__snprintf_chk'):
                fmt = s.cstr(r(4) if name in ('__vsnprintf_chk', '__snprintf_chk') else r(3) if name == '__sprintf_chk' else r(2))
                s.log.append(f'snprintf({fmt!r})')
                uc.mem_write(r(0), b'/FMT' + bytes(1)); return s.ret(4)
            if name in ('access', 'stat', 'lstat', 'faccessat', 'fstatat'):
                p = s.cstr(r(1) if name in ('faccessat', 'fstatat') else r(0)); s.log.append(f'{name}({p!r})')
                return s.ret(0 if p in exists else -1 & 0xffffffffffffffff)
            if name in QUIET: return s.ret(s.malloc(r(0)) if name == 'malloc' else 0)
            return super()._hook(uc, addr, size, _)
    u = V(); u.i = u.j = 0; u.lenient = True
    for j in JNI: u.stub(j, lambda u: 0)
    out = u.malloc(0x400)
    try: u.call(fn, out, 0x2000, 0, 0, limit=3_000_000)
    except Exception as e: u.log.append(f'!! {type(e).__name__}: {str(e)[:60]}')
    return u.log


if __name__ == '__main__':
    args, funcs, opt = sys.argv[1:], [], {'--line': [], '--dir': [], '--exists': []}
    while args:
        a = args.pop(0)
        if a in opt: opt[a].append(args.pop(0))
        else: funcs.append(int(a, 16))
    lines = [l.encode() + b'\n' for l in opt['--line']] or [b'x\n']
    for f in funcs:
        log = run(f, lines, [d.encode() for d in opt['--dir']], set(opt['--exists']))
        print(f'sub_{f:x}: ' + ' ; '.join(dict.fromkeys(log)))
