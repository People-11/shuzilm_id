# What the other scripts need from libdu.so's ELF headers, read directly (no readelf, no intermediate files):
#   relative(data)  {GOT slot: target} for R_AARCH64_RELATIVE (the encrypted-string table lives here)
#   globdat(data)   {GOT slot: (value, symbol)} for R_AARCH64_GLOB_DAT (OLLVM's opaque-predicate globals x / y)
#   plt(data)       {GOT slot: symbol} for R_AARCH64_JUMP_SLOT (the libc functions)
#   funcs(data)     sorted function start addresses, from .eh_frame_hdr
# usage: elf.py <libdu.so> funcs   -> one start address per line (the file the harness's FNTRACE=<file> wants)
import struct, sys

RELATIVE, GLOB_DAT, JUMP_SLOT = 1027, 1025, 1026


def _sections(data):
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    secs = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    names = secs[shstrndx][4]
    out = {}
    for name, typ, flags, addr, off, size, link, info, align, entsize in secs:
        n = data[names + name:data.index(b'\0', names + name)].decode()
        out[n] = (addr, off, size, entsize)
    return out


def _relocs(data):
    s = _sections(data)
    _, symoff, _, syment = s['.dynsym']
    stroff = s['.dynstr'][1]
    for sec in ('.rela.dyn', '.rela.plt'):
        if sec not in s: continue
        _, off, size, _ = s[sec]
        for i in range(0, size, 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off + i)
            sym = info >> 32
            name, value = '', 0
            if sym:
                st_name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', data, symoff + sym * syment)
                name = data[stroff + st_name:data.index(b'\0', stroff + st_name)].decode()
            yield slot, info & 0xffffffff, addend, name, value


def relative(data):
    return {slot: addend for slot, typ, addend, _, _ in _relocs(data) if typ == RELATIVE}


def globdat(data):
    return {slot: (value, name) for slot, typ, _, name, value in _relocs(data) if typ == GLOB_DAT}


def plt(data):
    return {slot: name for slot, typ, _, name, _ in _relocs(data) if typ == JUMP_SLOT}


def funcs(data):
    addr, off, _, _ = _sections(data)['.eh_frame_hdr']
    ver, _, cnt_enc, tbl_enc = data[off:off + 4]
    assert ver == 1 and cnt_enc == 0x03 and tbl_enc == 0x3b, 'unexpected .eh_frame_hdr encoding'
    n, = struct.unpack_from('<I', data, off + 8)
    return sorted(addr + struct.unpack_from('<i', data, off + 12 + 8 * i)[0] for i in range(n))


if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    if sys.argv[2:] == ['funcs']:
        print('\n'.join(f'{f:#x}' for f in funcs(d)))
