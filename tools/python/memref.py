# usage: memref.py so addr_hex... -> code sites that access these absolute addresses via adrp+ldr/str/add, or via GOT slots pointing at them
import sys, re
from capstone import *
d=open(sys.argv[1],'rb').read(); md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
targets={int(a,16) for a in sys.argv[2:]}
got={}
for line in open(__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '..', 'data', 'relocs.txt')):
    m=re.match(r'\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_AARCH64_RELATIVE\s+([0-9a-f]+)',line)
    if m and int(m.group(2),16) in targets: got[int(m.group(1),16)]=int(m.group(2),16)
print('got slots:',{hex(k):hex(v) for k,v in got.items()})
T0,T1=0x3d6c4,0x3d6c4+0x115308
regs={}; pc=T0
while pc<T1:
    n=0
    for i in md.disasm(d[pc:T1],pc):
        n+=1; pc=i.address+4
        ops=[o.strip() for o in i.op_str.split(',')]
        if i.mnemonic=='adrp': regs[ops[0]]=int(ops[1].lstrip('#'),16); continue
        mm=re.search(r'\[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]',i.op_str)
        if mm and mm.group(1) in regs:
            a=regs[mm.group(1)]+int(mm.group(2) or '0',0)
            if a in targets or a in got: print(hex(i.address),i.mnemonic,i.op_str,'->',hex(a))
        if i.mnemonic=='add' and len(ops)==3 and ops[1] in regs and ops[2].startswith('#'):
            a=regs[ops[1]]+int(ops[2][1:],0)
            if a in targets: print(hex(i.address),'add',i.op_str,'->',hex(a))
    if n==0: pc+=4
