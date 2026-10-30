import sys
data = open(sys.argv[1], 'rb').read()
for a in sys.argv[2:]:
    a = int(a, 16); out = []; k = 0
    while data[a + 2*k + 1] and k < 300:
        out.append(((data[a + 2*k + 1] - 1) ^ k) & 0xff); k += 1
    print(hex(a), bytes(out))
