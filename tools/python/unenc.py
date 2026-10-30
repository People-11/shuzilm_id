# usage: unenc.py <enc>...  -> libdu mode 2/3 values decoded (inverse of shuffle, then every char - 1)
import sys
def shuffle(s):
    n = len(s); m = n // 2; out = [s[m]] if n % 2 else []
    for i in range(m): out += [s[n - 1 - i], s[m - 1 - i]]
    return ''.join(out)
def unenc(e):
    n = len(e); m = n // 2; s = [''] * n; k = 0
    if n % 2: s[m] = e[0]; k = 1
    for i in range(m): s[n - 1 - i] = e[k]; s[m - 1 - i] = e[k + 1]; k += 2
    return ''.join(chr(ord(c) - 1) for c in s)
assert unenc(shuffle('bcd')) == 'abc' and unenc(shuffle('bcde')) == 'abcd'
for a in sys.argv[1:]: print(repr(a), '->', repr(unenc(a)))
