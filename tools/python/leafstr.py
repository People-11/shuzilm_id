# usage: leafstr.py func_hex...  -> run each leaf collector under unicorn with every libc call logged (string args)
# and the SDK's JNI helpers stubbed to 0, to read the paths / commands it builds from stack-XOR strings
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ucall
JNI = [0xf7cd8, 0xf5088, 0xf5348, 0xf53f0, 0xf7ed4, 0xf7dd8, 0xf83c8, 0xf8550, 0xf8668, 0xf78d8, 0xf77d8, 0xf76a8,
       0xf55d8, 0xf5634, 0xf5830, 0xf59a8, 0xf6004, 0xf6448, 0xf5f20, 0xf5c28, 0xf3274, 0xf367c, 0xf34ec, 0xe9e70,
       0x13fe10, 0xedbfc, 0xf02ac, 0xf07fc, 0xf0378, 0xf220c, 0xf2160]
for a in sys.argv[1:]:
    f = int(a, 16)
    u = ucall.U(); u.lenient = True
    for j in JNI: u.stub(j, lambda u: 0)
    u.stub(0x13fe10, lambda u: 34)
    try: u.call(f, 0x1000, 0x2000, 0, 0, limit=2_000_000)
    except Exception as e: u.log.append(f'!! {type(e).__name__}: {str(e)[:80]}')
    print(f'sub_{f:x}:', ' ; '.join(u.log[:12]))
