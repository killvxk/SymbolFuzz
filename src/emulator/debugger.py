#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Debugger.py
Create by  : Bluecake
Description: A debug tool for x86 and x86_64 program emulate
"""

from emulator import Emulator, UnsupportArchException
from utils import *
from pwn import disasm
import logging 

###############################################################################
#                                  Main Class                                 #
###############################################################################
class Debugger(Emulator):
    """Debug class for Emulator

    Attributes:
        show_inst 
        show_output

        breakpoints
        nextpc
        stopped
        last_cmd
    """

    def __init__(self, binary, dumpfile=''):

        super(Debugger, self).__init__(binary, dumpfile)
        
        self.show_inst = True
        self.show_output = True
        
        self.breakpoints = {}
        self.nextpc = None
        self.stopped = True      # whether to stop at next instruction
        self.last_cmd = ''


    """
    self-defined function for command reg
    """
    def show_register(self):
        if self.arch == 'x86':
            reg_list = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp', 'eip']

        elif self.arch == 'x64':
            reg_list = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp', 
                'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']

        else:
            raise UnsupportArchException(self.arch)

        for reg in reg_list:
            value = self.getreg(reg) 
            print '%s: %s' % (reg.rjust(3, ' '), hex(value).strip('L'))


    """
    self-defined function for command stack
    """
    def show_stack(self, size=10):
        if self.arch == 'x86':
            esp = self.getreg('esp')
            for i in range(size):
                value = self.getuint32(esp+i*4) 
                print '0x%x:  ' % (esp+i*4) + hex(value).strip('L')

        elif self.arch == 'x64':
            rsp = self.getreg('rsp')
            for i in range(size):
                value = self.getuint64(rsp+i*8) 
                print '0x%x:  ' % (rsp+i*8) + hex(value).strip('L')

        else:
            raise UnsupportArchException(self.arch)

        # elif Triton.getArchitecture() == ARCH.X86_64:
        #     rsp = Triton.getConcreteRegisterValue(Triton.registers.rsp)
        #     for i in range(10):
        #         value = Triton.getConcreteMemoryValue(MemoryAccess(rsp+i*8, CPUSIZE.QWORD))
        #         print '0x%x:  ' % (rsp + i*8) + hex(value).strip('L')


    """
    self-defined function for command x
    """
    def memory_x(self, cmd):

        Triton = self.triton
        args = cmd.split(' ')[1:]

        if len(args) == 1:

            addr = int(args[0], 16)
            if self.arch == 'x86':
                value = self.getuint32(addr) 

            else:
                raise UnsupportArchException(self.arch)

            print '0x%x:  ' % addr + hex(value).strip('L')

        elif len(args) == 2 and args[1] == '-s':

            addr = int(args[0], 16)
            content = self.getMemoryString(addr)
            print '0x%x: "%s"' % (addr, content) 

    
    """
    self-define function for command break
    """
    def set_breakpoint(self, addr):
        self.breakpoints[addr] = True

    """
    self-define function for command listbreak
    """
    def list_breakpoint(self):
        for addr, enabled in self.breakpoints.items():
            if enabled:
                print 'breapoint at %s is enabled' % hex(addr).strip('L')
            else: 
                print 'breapoint at %s is disabled' % hex(addr).strip('L')


    """
    breakpint function
    """
    def del_breakpoint(self, cmd):
        addr = int(cmd.split(' ')[1], 16)
        self.breakpoints[addr] = False


    """
    self-defined function for command next
    """
    def next_instruction(self):
        pass


    """
    self-defined function for command step
    """
    def step_instruction(self):
        pass

    
    """
    Parse user_input command and stop at breakpoints
    Probably like a debugger
    """
    def parse_command(self):
        """
        Arguments
            pc: current pc address
            handler: process an instruction, argument is pc address.
        """
        pc = self.getpc()

        def check_breakpoint(pc):
            if not self.breakpoints.has_key(pc):
                return False
            elif self.breakpoints[pc] is True:
                return True
            return False

        if self.stopped or check_breakpoint(pc):
            
            if self.last_cmd in ['ni', 'c']: 
                print '-'* 25 + ' register ' + '-'*25
                self.show_register()

                print '-'* 25 + '   code   ' + '-'*25
                opcode = self.getMemory(pc, 32)
                lines = disasm(opcode).splitlines()
                for i in range(5):
                    line = lines[i]
                    addr, disasm_code = line[:line.index(":")], line[line.index(":"):]
                    new_addr = pc + int(addr, 16)
                    print hex(new_addr) + disasm_code

                print '-'* 25 + '   stack  ' + '-'*25
                self.show_stack()

            if check_breakpoint(pc):
                print 'Breakpoint at ' + hex(pc).strip('L')
                self.stopped = True

            cmd = raw_input("> ").strip('\n')
            if not cmd:
                if self.last_cmd:
                    cmd = self.last_cmd
                else:
                    while not cmd:
                        cmd = raw_input("> ").strip('\n')

            self.last_cmd = cmd.split(' ')[0]

            if cmd.startswith('b ') or cmd.startswith('break '):
                addr = int(cmd.split(' ')[1], 16)
                self.set_breakpoint(addr)
                return pc

            elif cmd in ['continue', 'c']:
                self.stopped = False
                return self.process() 
            
            elif cmd.startswith('db'):
                self.del_breakpoint(cmd)
                return pc

            elif cmd in ['listbreak', 'lb']:
                self.list_breakpoint()
                return pc

            elif cmd in ['next', 'n', 'ni']:
                return self.process()

            elif cmd in ['reg', 're', 'r']:
                self.show_register()
                return pc               

            elif cmd == 'stack':
                self.show_stack()
                return pc               

            elif cmd.startswith('x '):
                self.memory_x(cmd)
                return pc               

            else:
                print 'unknown command'
                return pc

        else:
            return self.process()


    """
    Ok, everything is prepared, just go and debug
    """
    def debug(self):
        self.initialize()

        log.info("Start debugging")

        pc = self.getpc()
        self.lastInstType = None

        while pc:    
            pc = self.parse_command(pc)
        log.info("Debugging done")
        return
