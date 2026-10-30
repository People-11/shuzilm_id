# usage: funcidx.py <so> <strings.txt>  -> per-function list of decrypted strings (uses .eh_frame_hdr)
import sys, struct, bisect
d = open(sys.argv[1], 'rb').read()
HDR = 0x147dc  # .eh_frame_hdr vaddr == file offset
ver, ptr_enc, cnt_enc, tbl_enc = d[HDR:HDR+4]
assert ver == 1 and cnt_enc == 0x03 and tbl_enc == 0x3b, (ver, cnt_enc, tbl_enc)
n = struct.unpack_from('<I', d, HDR + 8)[0]
starts = sorted(HDR + struct.unpack_from('<i', d, HDR + 12 + 8*i)[0] for i in range(n))
idx = {}
for line in open(sys.argv[2]):
    a, sites, s = line.rstrip('\n').split('\t', 2)
    for site in sites.split(','):
        f = starts[bisect.bisect_right(starts, int(site, 16)) - 1]
        idx.setdefault(f, []).append(s)
for f in sorted(idx):
    print(f"{f:#x}\t{' | '.join(dict.fromkeys(idx[f]))}")
