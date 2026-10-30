# usage: apkcert.py file.apk out.der -> extract first signer certificate from APK Signature Scheme v2/v3 block
import sys, struct, hashlib
d = open(sys.argv[1], 'rb').read()
eocd = d.rfind(b'PK\x05\x06')
cd_off = struct.unpack_from('<I', d, eocd + 16)[0]
assert d[cd_off - 16:cd_off] == b'APK Sig Block 42', 'no signing block'
blk_size = struct.unpack_from('<Q', d, cd_off - 24)[0]
start = cd_off - blk_size - 8
assert struct.unpack_from('<Q', d, start)[0] == blk_size
pos, end = start + 8, cd_off - 24
def lp(buf, o):  # uint32 length-prefixed
    n = struct.unpack_from('<I', buf, o)[0]; return buf[o + 4:o + 4 + n], o + 4 + n
certs = {}
while pos < end:
    ln, pid = struct.unpack_from('<QI', d, pos)
    val = d[pos + 12:pos + 8 + ln]
    pos += 8 + ln
    if pid in (0x7109871a, 0xf05368c0):
        signers, _ = lp(val, 0)
        signer, _ = lp(signers, 0)
        signed_data, _ = lp(signer, 0)
        digests, o = lp(signed_data, 0)
        certseq, o = lp(signed_data, o)
        cert, _ = lp(certseq, 0)
        certs[hex(pid)] = cert
for k, c in certs.items():
    print(k, len(c), 'md5', hashlib.md5(c).hexdigest().upper(), 'sha1', hashlib.sha1(c).hexdigest().upper())
c = next(iter(certs.values()))
open(sys.argv[2], 'wb').write(c)
