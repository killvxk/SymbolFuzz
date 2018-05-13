from pwn import *
f = open('eip.in')
input = f.read()
pro = process('./bof',aslr=False)
gdb.attach(pro,'b *0x80489B4')
pro.send(input)
pro.interactive()