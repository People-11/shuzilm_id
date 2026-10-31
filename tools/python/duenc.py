# libdu field encoding (put modes 2 / 3 / 10), keyed by the report's 2cO time string.
# usage: duenc.py <2cO> enc|dec <value>...      e.g.  duenc.py 1791105420.764024281 dec bb_p   -> WIFI
#
# P = atoi of the last 3 characters of 2cO with '.' dropped (sub_14acbc, stored in data_161704 once per query;
# 2cO is "%ld.%ld" of clock_gettime(CLOCK_REALTIME), sub_c6df0). From P:
#   shift K   = P % 100 % 57 + 1, applied to each char within printable ASCII 0x20..0x7e (wrapping)
#   shuffle   = variant (P // 100) % 4
#   mode 10   = drop the char at n-1-P%10 (n > 9, else the last), checksum MD5_UPPER(str(sum of codes + P%100//10))[:7]
import hashlib, sys


def p_of(two_co):
    return int(two_co[-3:].replace('.', '') or 0)


def shuffle(s, v):
    n, m = len(s), len(s) // 2
    if v == 0:  # sub_df720: middle first, then pairs s[n-1-i], s[m-1-i]
        return (s[m] if n % 2 else '') + ''.join(s[n - 1 - i] + s[m - 1 - i] for i in range(m))
    if v == 1:  # pairs s[n-1-i], s[i], middle last
        return ''.join(s[n - 1 - i] + s[i] for i in range(m)) + (s[m] if n % 2 else '')
    if v == 2:  # from the last char backwards in steps of 2, then from the one before it
        return s[n - 1::-2] + s[n - 2::-2]
    return s[0::2] + s[1::2]  # v == 3


def unshuffle(e, v):
    n = len(e)
    idx = shuffle(''.join(chr(0x100 + i) for i in range(n)), v)
    out = [''] * n
    for pos, c in enumerate(idx): out[ord(c) - 0x100] = e[pos]
    return ''.join(out)


def shift(s, k):
    return ''.join(chr((ord(c) - 0x20 + k) % 95 + 0x20) for c in s)


def enc(value, p):
    return shuffle(shift(value, p % 100 % 57 + 1), p // 100 % 4)


def dec(e, p):
    return shift(unshuffle(e, p // 100 % 4), -(p % 100 % 57 + 1))


def twin(value, p):  # mode 10: (encoded value with one char dropped, checksum under "s" + key)
    n = len(value)
    if n <= 1: return enc(value, p), 'CFCD208'
    i = n - 1 - p % 10 if n > 9 else n - 1
    chk = hashlib.md5(str(sum(map(ord, value)) + p % 100 // 10).encode()).hexdigest().upper()[:7]
    return enc(value[:i] + value[i + 1:], p), chk


# observed in the harness (NS3=<P> forces the last 3 digits of 2cO; ANDROID_ID as given)
AID = '7be317f3baa70ddb'
for p, foo, sfoo in [(0, '4ege81284bfbcc8', '3BF55BB'), (281, '{Iz{ J~P}PzLPL{', '7EB3C8B'),
                     (7, ';jnl?l98;?miji?', '3BF55BB'), (99, '..^0b0\\[^b1-.-b', '6C8DBA7'),
                     (100, 'e8ec1f84b2b8cg4', '3BF55BB'), (999, '.b0.01[^b\\-b-^.', '6C8DBA7')]:
    assert twin(AID, p) == (foo, sfoo), (p, twin(AID, p))
for p, mch in [(0, 'JJGX'), (281, 'bb_p'), (7, 'QQN_'), (99, 'ttq#'), (100, 'JXGJ'), (999, 't#qt'),
               (56, '## 1'), (57, 'JJGX'), (64, 'QQN_'), (80, 'aa^o')]:
    assert enc('WIFI', p) == mch and dec(mch, p) == 'WIFI', (p, enc('WIFI', p))
U = '0123456789abcdef'
for p, foo in [(0, '8f7e6d5c4b3:291'), (100, 'f1e2d3c4b5:6978'), (200, 'fdb97531ec:8642'), (300, '13579bdf2468:ce'),
               (3, ';j:i9h8f7e6=5<4')]:
    assert twin(U, p)[0] == foo, (p, twin(U, p))
assert p_of('1791105420.764024281') == 281 and p_of('1793367275.234000000') == 0

if __name__ == '__main__' and len(sys.argv) > 3:
    p = p_of(sys.argv[1])
    for v in sys.argv[3:]:
        print(repr(v), '->', repr(enc(v, p) if sys.argv[2] == 'enc' else dec(v, p)))
