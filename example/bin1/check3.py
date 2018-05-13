from pwn import *
context.log_level = 'debug'
f = open('./exp/exp.0','rb')
input = f.read()
pro = process('./bin')
gdb.attach(pro)
#raw_input()
#print input
pro.send(input)
#print pro.recv()
pro.interactive()
