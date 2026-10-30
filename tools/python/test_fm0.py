# sub_4afb4 (fM0) under unicorn vs the Kotlin port in DuClient.factoryMac, on random wlan0 / wlan1 / p2p0 MACs
import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import random, ucall
def port(sdk, w0, w1, p):
    bad = lambda m: m is None or (m[1] if len(m) > 1 else ' ') in '26ae'
    if sdk < 28 or not bad(w0): return w0
    if w1 is not None and p is not None and len(w1) == len(p) and len(w1) <= 18 and (len(w1) < 5 or w1[2:-2] == p[2:-2]):
        return w1[:15] + p[15:] if len(w1) >= 16 else None
    if w1 is not None and not bad(w1):
        prev, last = w1[-2], w1[-1]
        tail = prev + '9' if last in 'aA' else ((prev if prev == '0' else chr(ord(prev) - 1)) + 'f') if last == '0' else prev + chr(ord(last) - 1)
        return w1[:-2] + tail
    return (p[:1] + '2' + p[2:]) if p is not None else w0
def mac(rng, base=None):
    if rng.random() < 0.2: return None
    h = '0123456789abcdef'
    b = base or [rng.choice(h) + rng.choice(h) for _ in range(6)]
    b = list(b)
    if rng.random() < 0.4: b[0] = rng.choice(h) + rng.choice('26ae0123')
    if rng.random() < 0.5: b[5] = rng.choice('0a' + h) + rng.choice('0aA1f9' + h)
    return ':'.join(b)
rng = random.Random(1)
bad = 0
for n in range(3000):
    base = [rng.choice('0123456789abcdef') + rng.choice('0123456789abcdef') for _ in range(6)]
    sdk = rng.choice([27, 28, 30, 34])
    w0, w1, p = mac(rng, base), mac(rng, base if rng.random() < 0.6 else None), mac(rng, base if rng.random() < 0.6 else None)
    u = ucall.U()
    u.stub(0x4adb4, lambda u: u.cstr_new(w0)); u.stub(0x13fe10, lambda u: sdk)
    u.stub(0xc2198, lambda u: u.cstr_new(w1)); u.stub(0xc21b8, lambda u: u.cstr_new(p))
    r = u.call(0x4afb4, 0x1000, 0x2000)
    got = u.cstr(r) if r else None
    exp = port(sdk, w0, w1, p)
    if got != exp:
        bad += 1
        if bad < 10: print('MISMATCH', sdk, w0, w1, p, 'native', got, 'port', exp)
print('cases', n + 1, 'mismatches', bad)
