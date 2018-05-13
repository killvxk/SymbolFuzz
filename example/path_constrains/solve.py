#!/usr/bin/env python
# coding=utf-8

"""
Module name: Branch Solve Test
Create by: Bluecake
Descript: A demo to pass the first check


"""

from emulator import *
import os
from pwn import u32

class SolveTest(Emulator):

    def __init__(self, binary, show=False, symbolize=True):
        super(SolveTest, self).__init__(binary, show=show, symbolize=symbolize)
        self.log = get_logger('solve.py', logging.INFO)

        # create pipe for SYSCALL read
        r, w = os.pipe()
        self.read = r
        self.write = w

    def solve_test1(self):
        self.initialize()
        log = self.log 
        
        log.info("test1 started");
        pc = self.getpc()
        os.write(self.write, "123aaa\n")
        os.write(self.write, "a"*100 + '\n')
        
        while pc:
            
            if pc == 0x08048952:
                """
                .text:0804894A                 push    [ebp+buffer]
                .text:0804894D                 call    atoi
                .text:08048952                 add     esp, 10h
                .text:08048955                 mov     [ebp+size], eax
                .text:08048958                 cmp     [ebp+size], 0
                .text:0804895C                 js      short loc_8048967
                """
                Triton = self.triton
                astCtxt = Triton.getAstContext()

                # Define constraint
                constraints = [Triton.getPathConstraintsAst()]

                eax_id = Triton.getSymbolicRegisterId(Triton.registers.eax)
                eax_symbol = Triton.getSymbolicExpressionFromId(eax_id)
                eax_ast = eax_symbol.getAst()
                
                # here we expect return value of atoi(buf) is 200.
                constraints.append(astCtxt.equal(eax_ast, astCtxt.bv(200, 32)))
                
                cstr  = astCtxt.land(constraints)

                print '[+] Asking for a model, please wait...'
                model = Triton.getModel(cstr)

                # Save new state
                for k, v in model.items():
                    print '[+]', v
                
                return

            pc = self.parse_command(pc)

        log.info("test1 ended");


    def solve_test2(self): 
        self.initialize()
        log = self.log 
        
        log.info("test1 started");
        pc = self.getpc()
        os.write(self.write, "200aaa\n")
        os.write(self.write, "a"*100 + '\n')

        data = range(100)
        while pc:
            if pc == 0x8048a2f:
                """ 
                .text:08048A1F                 add     esp, 10h
                .text:08048A22                 sub     esp, 8
                .text:08048A25                 push    [ebp+out_put]
                .text:08048A28                 lea     eax, [ebp+b]
                .text:08048A2E                 push    eax
                .text:08048A2F                 call    sprintf

                Here, we want a valid sprintf format like "%x%x%x%x"
                """
                Triton = self.triton
                astCtxt = Triton.getAstContext()

                # Define constraint
                constraints = [Triton.getPathConstraintsAst()]

                # get format addr
                esp = self.getreg('esp')
                format_addr = self.getuint32(esp + 4)
                target_format = "%p-%p-%p"
                for i, v in enumerate(target_format):
                    byteId = Triton.getSymbolicMemoryId(format_addr + i)
                    byteSym = Triton.getSymbolicExpressionFromId(byteId)
                    byteAst = byteSym.getAst()
                    constraints.append(astCtxt.equal(byteAst, astCtxt.bv(ord(v), 8)))

                cstr  = astCtxt.land(constraints)

                print '[+] Asking for a model, please wait...'
                model = Triton.getModel(cstr)

                # Save new state
                for k, v in model.items():
                    print '[+]', v
                    index = int(v.getName().replace('SymVar_', ''))
                    data[index] = v.getValue()
                
                with open('input', 'w') as f:
                    data = ''.join(map(chr, data))
                    f.write(data)

                return

            # pc = self.parse_command(pc)
            pc = self.process()
        


if __name__ == '__main__': 
    solver = SolveTest('./bin', show=False)
    solver.solve_test2()
