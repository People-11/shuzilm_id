import sys
from capstone import *
d=open(sys.argv[1],'rb').read(); md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
a,b=int(sys.argv[2],16),int(sys.argv[3],16)
pc=a
while pc<b:
    n=0
    for i in md.disasm(d[pc:b],pc):
        print(hex(i.address),i.mnemonic,i.op_str); n+=1; pc=i.address+4
    if n==0: print(hex(pc),'.word',d[pc:pc+4].hex()); pc+=4
