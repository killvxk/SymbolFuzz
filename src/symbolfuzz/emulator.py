#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Emulator.py
Create by  : Bluecake
Description: A tool for x86 and x86_64 program emulate
"""

from pwn import log, asm, context, ELF, process, gdb
from syscall import *
from triton import * 
from utils import *
import subprocess
import tempfile
import os, sys
import string
import lief
import time

from basic import *
import gc



###############################################################################
#                          Emulation Exception                                #
###############################################################################
class IllegalPcException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Eip address [0x%x] is illegal" % pc)
        else:
            raise UnsupportArchException(arch)


class IllegalInstException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Instruction at [0x%x] is illegal" % pc)
        else:
            raise UnsupportArchException(arch)


class InfinityLoopException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Encounter inifinity instruction at 0x%x" % pc)
        else:
            raise UnsupportArchException(arch)


class MemoryAccessException(Exception):
    def __init__(self, pc, addr):
        Exception.__init__(self, "Invalid memory [0x%x] access instruction at 0x%x" % (addr, pc))

############################################################################### 
#                                  Main Class                                 #
###############################################################################
class Emulator(Basic):
    """Basic program interpreter

    This is the basic program interpreter. It provoide interfaces 
    to emulate program running

    Attributes:
        binary: A string, stores the path of binary. It can be 
                absolute path or relative path.

        dumpfile: A string, stores the path of memory snapshot 
                file. It can be absolute path or relative path.
        
        show_inst: A boolean, switch to show every executed instruction 

        show_output: A boolean, switch to show program output
        
        root_dir: A string, source file root directory.

        arch: A string, program architecture like "x86". 

        read_count: Total bytes of read from any file descriptor.

        last_pc: Pc address of last executed instruction.

        inst_count: Total number of executed instructions.
        
        syshook: A Syscall instance, syscall call filter. 

        callbacks: A dict, callback functions for syscalls,

        opcodeCache: A dict, stores the the map of assembly code
                and binary code.  Format is like 
                {
                    'arch':
                        {   
                            'mov eax, 0x1': '\xde\xad\xbe\xef'
                            'mov ebx, 0x1': '\xde\xaa\xbe\xef'
                        }
                }

        opcodeCacheFile: A string, stores the path of opcodeCache 
                dict.

        running: A boolean value, true means the program is active.

        syscallFail: A boolean value, false means last syscall
                failed.
        
    """

    def __init__(self, binary, dumpfile=""):
        """Emulator Constructor
        
        Args:
            binary:     path of executable binary 
            dumpfile:   path of memory snapshot file
        """
        super(Emulator, self).__init__()

        self.binary = binary
        self.dumpfile = dumpfile
        self.show_inst = True
        self.show_output = True
        self.memAccessCheck = False
        self.memoryAccessError = False
        
        self.root_dir = os.path.dirname(__file__)

        # elf = ELF(binary)
        # if elf.get_machine_arch() in ['x86', 'i386']:
        #     self.arch = 'x86'
        # del elf
        self.arch = 'x86'

        SupportedArch = ['x86']
        if self.arch not in SupportedArch:
            raise UnsupportArchException(self.arch)
        
        if self.arch == 'x86':
            context.arch = 'i386'

        self.read_count = 0
        self.last_pc = 0
        self.inst_count = 0
        self.syshook = Syscall(self.arch)
        
        self.opcodeCacheFile = "/tmp/OpcodeCache.txt"
        if os.path.exists(self.opcodeCacheFile):
            try:
                f = open(self.opcodeCacheFile)
                self.opcodeCache = eval(f.read())
            
            except Exception as e:
                log.debug(e)
                self.opcodeCache = { self.arch: {} }

        else:
            self.opcodeCache = { self.arch: {} }

        self.memoryCache = list() 

        self.running = True
        self.syscallFail = False
        self.callbacks = {}

    def snapshot(self, seed='', dumpfile=''):
        """Automatically take memory snapshot on the entrypoint of main()
            or other point
        """
        if dumpfile == '':
            dumpfile = self.dumpfile

        if os.path.exists(dumpfile):
            return 

        # Make the binary file executable
        try:
            os.chmod(self.binary, 0o777)
        except Exception as e:
            print e

        _, debug_file = tempfile.mkstemp()
        peda_path = "/usr/share/peda/peda.py"
        # type_path = self.root_dir + '/type'
        # elf = lief.parse(self.binary) 

        # with open(debug_file, 'w') as f:
        #     content = "source %s\n" \
        #             "break * 0x%x\n" \
        #             "start\n" \
        #             "nextcall\n" \
        #             "add-symbol-file %s 0\n%s\n" \
        #             "continue\nfulldump %s\n" \
        #             "quit\n"
        #     if self.arch == 'x86':
        #         breakpoint = "break * *(uint32_t)$esp"

        #     else:
        #         breakpoint = "break * $rdi"

        #     content = content % (peda_path, elf.entrypoint, type_path, breakpoint, self.dumpfile)
        #     f.write(content)
        
        with open(debug_file, 'w') as f:
            content = "source %s\n" \
                    "set $eax=3\n" \
                    "set $eip=$eip-2\n" \
                    "fulldump %s\n" \
                    "quit\n" % (peda_path, dumpfile)

            f.write(content)

        try:
            p = process(self.binary)
            log.info('try to dump memory with seed ' + repr(seed))
            # gdb.attach(p)
            if seed:
                p.send(seed)
            cmd = "gdb -nx -command=%s --pid=%d" % (debug_file, p.pid)
            log.info(cmd)

            # Run gdb and dump memory with patched peda
            subprocess.check_output(cmd, shell=True, stderr=None)
            # os.system(cmd)
            p.close()

        except Exception as e:
            print e
    
    def setreg(self, reg, value):
        """Set targeted register

        Args:
            reg: Register name
            value: If arch is x86, it should be a uint32 value.
                    If arch is x64, it should be a uint64 value.
        """
        Triton = self.triton
        return eval('Triton.setConcreteRegisterValue(Triton.registers.%s, %d)' % (reg, value))

    def getreg(self, reg):
        """Retrieve targetd register
        
        Args:
            reg: Register name

        Return:
            If arch is x86, it should return a uint32 value.
            If arch is x64, it should return a uint64 value.

        """
        Triton = self.triton
        return eval('Triton.getConcreteRegisterValue(Triton.registers.%s)' % (reg,))


    
    def setpc(self, address):
        """ Set new pc address

        Args:
            value: new pc address
        """

        if self.arch == 'x86':
            return self.setreg('eip', address)

        elif self.arch == 'x64':
            return self.setreg('rip', address)

        else:
            raise UnsupportArchException(self.arch)


    def getpc(self):
        """Retrieve current PC address

        Return:
            uin32 or uint64, current pc address
        """
        if self.arch == 'x86':
            return self.getreg('eip')

        elif self.arch == 'x64':
            return self.getreg('rip')

        else:
            raise UnsupportArchException(self.arch)

    def getMemoryString(self, addr):
        """Retrieve string terminated with null byte
        
        Args:
            addr: memory address 

        Return:
            A string, stored in targeted memory
        """
        Triton = self.triton

        s = ""
        index = 0
        while Triton.getConcreteMemoryValue(addr + index):
            c = chr(Triton.getConcreteMemoryValue(addr + index))
            if c == '\x00': 
                break
            s += c
            index += 1
        return s

    def getMemory(self, addr, size):
        """ Retrieve a block of data 
        
        Args:
            addr: memory address you want to read from
            size: size of bytes you want to read

        Return:
            A string, memory content of targeted address
        """
        return self.triton.getConcreteMemoryAreaValue(addr, size)
    
    def writeMemory(self, addr, content):
        """Write data into memory

        Args:
            addr: memory address to write
            content: content to be written into memory
        """

        if type(content) == int or type(content) == long:

            if self.arch == 'x86':
                mem = MemoryAccess(addr, 4)

                # Due to the memory cache mechanism, make the 
                # target memory area mapped first. 
                if not self.triton.isMemoryMapped(addr):
                    self.triton.getConcreteMemoryValue(mem)

                self.triton.setConcreteMemoryValue(mem, content)

            elif self.arch == 'x64':
                mem = MemoryAccess(addr, 8)

                if not self.triton.isMemoryMapped(addr):
                    self.triton.getConcreteMemoryValue(mem)

                self.triton.setConcreteMemoryValue(mem, content)

        else:
            offset = 0
            while offset < len(content) :
                if not self.triton.isMemoryMapped(addr + offset):
                    MemoryAccess(addr + offset, 0x40)
                offset += 0x40

            self.triton.setConcreteMemoryAreaValue(addr, content)

            

    def getuint32(self, addr):
        """Retrieve uint32 value of target address

        Args:
            addr: memory address

        Return:
            An uint32 value
        """
        mem = MemoryAccess(addr, 4)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)

    def getuint64(self, addr):
        """Retrieve uint64 value of target address
        
        Args:
            addr: memory address

        Return:
            An uint64 value
        """
        mem = MemoryAccess(addr, 8)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)
    
    def asm(self, code):
        """Return assemble code

        Args:
            code: A string, assembly code like 'mov eax, ebx'

        Return:
            A String, binary code compiled with pwn.asm()
        """
        
        if code not in self.opcodeCache[self.arch]:
            bincode = asm(code)
            self.opcodeCache[self.arch][code] = bincode

            with open(self.opcodeCacheFile, 'wb') as f:
                f.write(repr(self.opcodeCache))
        
        return self.opcodeCache[self.arch][code]

    def load_dump(self):
        """Recover memory, registers with dumpfile"""

        Triton = self.triton

        # Open the dump
        fd = open(self.dumpfile)
        log.debug('load memory dumpfile ' + self.dumpfile)
        data = eval(fd.read())
        fd.close()

        # Extract registers and memory
        regs = data[0]
        mems = data[1]
        gs_8 = data[2]

        context.arch = 'i386'

        # Load memory into memoryCache
        log.debug('Define memory areas')
        for mem in mems:
            start = mem['start']
            end   = mem['end']
            name  = mem['name']
            log.debug('Memory caching %x-%x' %(start, end))
            if mem['memory']:
                self.memoryCache.append({
                    'start':  start,
                    'size':   end - start,
                    'memory': mem['memory'],
                    'name': name
                })

        # Make sure to restore gs register first
        from pwn import u32
        self.setreg('gs', regs['gs'])
        for i in range(7):
            log.debug('Restore gs[0x%x]' % (i*4))
            v = u32(self.getMemory(gs_8 + i*4, 4))
            write_gs = ['mov eax, %s' % hex(v), 'mov gs:[%d], eax' % (i*4)]
            for inst in write_gs:
                asm_code = self.asm(inst)
                instruction = Instruction()
                instruction.setOpcode(asm_code)
                instruction.setAddress(0)
                Triton.processing(instruction)

        # Load registers into the triton
        log.debug('Define registers')
        for reg, value in regs.items():
            log.debug('Load register ' + reg)
            self.setreg(reg, value)

        return       

    def memoryCaching(self, triton, mem):
        """Callback: Speed up the procedure of load_dump"""

        addr = mem.getAddress()
        size = mem.getSize()
        # print "memoryCache is called", hex(addr), hex(size)
        for index in range(size):
            if not triton.isMemoryMapped(addr, size):
                for m in self.memoryCache:
                    if addr >= m['start'] and addr + size < m['start'] + m['size']:
                        # print 'memory check successful'
                        offset = addr - m['start']
                        value = m['memory'][offset : offset + size]
                        triton.setConcreteMemoryAreaValue(addr, value)
                        return

        # not stable, be careful to use it
        if self.memAccessCheck and not self.isAddress(addr):
            pc = self.getpc()
            self.memoryAccessError = (pc, addr)
            self.running = False

        return   

    # def checkAccess(self, switch):
    #     """Switch to checking memory access address

    #     Args:
    #         switch: boolean, if True, do memory access check
    #     """
    #     self.memAccessCheck = switch

    def isAddress(self, addr):
        """Check whether a specific address is a valid address
        
        Args:
            addr: instruction address

        Return:
            boolean, true is valid, false is invalid.
        """

        for m in self.memoryCache:
            if addr >= m['start'] and addr < m['start'] + m['size']:
                return True
        return False 
    

    def callback_read(self, fd, addr, length):
        """Callback for syscall read"""
        
        log.debug('[callback_read] fd: %d, addr: %s, length: %d' % (fd, hex(addr), length))
        if 'read_before' in self.callbacks:
            self.callbacks['read_before'](self, fd, addr, length)
            if not self.running:
                return 0
        
        if length > 0x100000:
            length = 0x100000

        if not self.isAddress(addr):
            self.running = False
            return 0

        # read evreything from /dev/zero which is filled with 'A'
        if hasattr(self, "dev_zero"):
            content = 'A' * length

        elif fd == 0:

            # hijack standard input
            if hasattr(self, 'stdin'):

                # input buffer defualt to be filled with 'A'
                if len(self.stdin) < length:
                    content = self.stdin.ljust(length, 'A')
                    self.stdin = ''

                # # read() is gonna finish reading when encounters '\n'
                # elif 0 <= self.stdin.find('\n') < length:
                #     content = self.stdin[:self.stdin.find('\n')+1]
                #     self.stdin = self.stdin[self.stdin.find('\n')+1:]

                else:
                    content = self.stdin[:length]
                    self.stdin = self.stdin[length:]

            # read from standard input
            else:
                content = raw_input()
                if len(content) < length and not content.endswith('\n'):
                    content += '\n'
                else:
                    content = content[:length]

        # read data from opened file
        else:
            content = os.read(fd,  length)
        
        self.writeMemory(addr, content)
        self.setreg('eax', len(content))
        
        if 'symbolize_check' in self.callbacks:
            check = self.callbacks['symbolize_check']
            for offset in range(len(content)):
                if check(self, self.read_count + offset):
                    log.debug("try to symbolize 0x%x, offset is %d" % (addr + offset, offset))
                    mem = MemoryAccess(addr + offset, 1)
                    self.triton.convertMemoryToSymbolicVariable(mem)

        if 'taint_check' in self.callbacks:
            check = self.callbacks['taint_check']
            for offset in range(len(content)):
                if check(self, self.read_count + offset):
                    log.debug("try to taint 0x%x, offset is %d" % (addr + offset, offset))
                    self.triton.taintMemory(addr + offset)

        if 'read_after' in self.callbacks:
            self.callbacks['read_after'](self, content)
        
        self.read_count += len(content)
        return len(content)

    def callback_write(self, fd, addr, length):
        """Callback for syscall write"""

        if 'write_before' in self.callbacks:
            self.callbacks['write_before'](self, fd, addr, length)

        if not self.isAddress(addr):
            log.warn('[callback_write] Invalid target memory address ' + hex(addr))
        
        # Check fd, may cause other problem, but just do it.
        # Just because file-related syscalls are not supported yet.
        if fd > 3:
            self.running = False
            return 0

        if length > 0x1000000:
            self.running = False
            return 0

        content = self.getMemory(addr, length)

        if self.show_output:
            os.write(fd, content)

        self.setreg('eax', len(content))

        if 'write_after' in self.callbacks:
            self.callbacks['write_after'](self, fd, addr, length)
        return len(content)


    def callback_exit(self, exit_value):
        """Callback for syscall exit and exit_group"""

        if 'syscall_exit' in self.callbacks:
            self.callbacks['syscall_exit'](self, exit_value)

        self.running = False
        self.setpc(0)
        return 0

    def callback_fstat64(self, fd, stat_buf):
        self.writeMemory(stat_buf + 0x10, 0x2000)
        self.setreg('eax', 0)
        return 0

    def callback_unsupported(self, *args):
        if 'noImplementSys' in self.callbacks:
            self.callbacks['noImplementSys'](self, *args)

    
    def initialize(self):
        """Prepare everything before starting emulate"""

        Triton = self.triton = TritonContext()

        if self.arch == 'x86':
            Triton.setArchitecture(ARCH.X86)
        else:
            raise UnsupportArchException(self.arch)

        # Define symbolic optimizations
        Triton.enableMode(MODE.ALIGNED_MEMORY, True)
        Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        Triton.addCallback(self.memoryCaching, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        
        if self.dumpfile == '':
            file_hash = md5(self.binary)            
            # Get dumpfile from entry of main()
            self.dumpfile = '/tmp/%s_%s_dump.bin' % (os.path.basename(self.binary), file_hash)

        if not os.path.exists(self.dumpfile):
            self.snapshot()

        self.load_dump()
        self.lastInstType = OPCODE.JMP

        self.syshook.add_callback("read", self.callback_read)
        self.syshook.add_callback("write", self.callback_write)
        self.syshook.add_callback("exit", self.callback_exit)
        self.syshook.add_callback("exit_group", self.callback_exit)
        self.syshook.add_callback("fstat64", self.callback_fstat64)
        self.syshook.add_callback("unsupported", self.callback_unsupported)

    def getSyscallRegs(self):
        """Retrieve args for syscall instruction

         Return:
            If arch is x86, return eax, ebx, ecx, edx, edi, esi, ebp
        """
        if self.arch == 'x86':
            eax = self.getreg('eax')
            ebx = self.getreg('ebx')
            ecx = self.getreg('ecx')
            edx = self.getreg('edx')
            esi = self.getreg('esi')
            edi = self.getreg('edi')
            ebp = self.getreg('ebp')
            return (eax, ebx, ecx, edx, esi, edi, ebp)
        else:
            raise UnsupportArchException(self.arch)

    def set_input(self, data):
        """Set input buffer
            
        Args:
            data: A string, input data that added to input buffer
        """

        if hasattr(self, 'stdin'):
            self.stdin += data
        else:
            self.stdin = data
            
    def symbolize_reg(self, reg):
        """ Symbolizing target register """

        log.debug("try to symbolize " + reg)
        treg = eval("self.triton.registers." + reg)
        self.triton.convertRegisterToSymbolicVariable(treg)
    
    def isRegisterSymbolized(self, reg):
        """ Check whether target register is symbolized

        Args:
            reg: A string, register name

        Return:
            true, if target register is symbolized
        """
        treg = eval("self.triton.registers." + reg)
        return self.triton.isRegisterSymbolized(treg)

    def isMemorySymbolized(self, addr):
        """ Check whether target memory is symbolized

        Args:
            addr: A uint32, memory address

        Return:
            true, if target memory is symbolized
        """
        return self.triton.isMemorySymbolized(addr)

    def isTainted(self, target):
        """ Check whether target data is influenced

        Args:
            target: memory address list or register name

        Return:
            true, if any byte of target memory is tainted
        """

        if type(target) == str:
            target = eval("self.triton.registers." + target)
            return self.triton.isRegisterTainted(target)

        else:
            for aByte in target:
                if self.triton.isMemoryTainted(aByte):
                    return True

        return False

    def instrument(self, opcode):
        if hasattr(self, 'inst'):
            inst = self.inst
        else:
            inst = Instruction()
            self.inst = inst

        bincode = self.asm(opcode)
        inst.setOpcode(bincode)
        inst.setAddress(0)
        self.triton.processing(inst)
   
    """
    Process only an instruction
    """
    def process(self):

        if not self.running:
            if self.memoryAccessError:
                pc, addr = self.memoryAccessError
                self.memoryAccessError = False
                raise MemoryAccessException(pc, addr)
            return 0
        
        pc = self.getpc()
        self.inst_count += 1

        if pc == self.last_pc:
            self.inst_loop += 1
            """When encounter unsupported instruction, the 
            program might get stuck in one instruction.
            """
            if self.show_inst >= 1000:
                raise InfinityLoopException(self.arch)
        else:
            self.inst_loop = 0

        opcode = self.getMemory(pc, 16)

        # Create the Triton instruction
        if hasattr(self, "instruction"):
            instruction = self.instruction
        else:
            instruction = Instruction()
            self.instruction = instruction

        instruction.setOpcode(bytes(opcode))
        instruction.setAddress(pc)
        
        Triton = self.triton
        Triton.disassembly(instruction)

        if instruction.getType() == OPCODE.MOVSD: 

            """
            For unknown reason, triton didn't work when meets instruction 
            like "rep mov", So I did some patch by hand
            """
            ecx = self.getreg('ecx')
            if ecx > 0x1000:
                ecx = 0x1000
            self.instrument("push eax")
            log.debug('try to patch "rep movsd"')
            for i in range(ecx):
                gadgets = ["mov eax, dword ptr [esi]", 
                            "mov dword ptr [edi], eax", 
                            "add esi, 4", 
                            "add edi, 4"]
                for gadget in gadgets:
                    self.instrument(gadget)

            self.instrument("pop eax")
            self.setpc(pc + instruction.getSize())

            return self.getpc()

        elif instruction.getType() == OPCODE.MOVSB:

            log.debug('try to patch "rep movsb"')
            ecx = self.getreg('ecx')
            if ecx > 0x1000:
                ecx = 0x1000
            self.instrument("push eax")

            for i in range(ecx):
                gadgets = ["mov al, byte ptr [esi]", 
                            "mov byte ptr [edi], al", 
                            "add esi, 1", 
                            "add edi, 1"]
                for gadget in gadgets:
                    self.instrument(gadget)

            self.instrument("pop eax")
            self.setpc(pc + instruction.getSize())
            return self.getpc()

        # Process
        self.triton.processing(instruction)
        if self.show_inst:
            print instruction

        if instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:

            if self.lastInstType not in [OPCODE.SYSENTER, OPCODE.INT] \
                    and instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:


                sysnum, arg1, arg2, arg3, arg4, arg5, arg6 \
                    = self.getSyscallRegs()
                
                if 'syscall_before' in self.callbacks:
                    self.callbacks['syscall_before'](self, sysnum, arg1, arg2, \
                            arg3, arg4, arg5, arg6)

                ret = self.syshook.syscall(sysnum, arg1, arg2, arg3, \
                    arg4, arg5, arg6)

                if 'syscall_after' in self.callbacks:
                    self.callbacks['syscall_before'](ret)

            self.setpc(pc + instruction.getSize())

        elif instruction.getType() == OPCODE.HLT:
            log.debug("Program stopped [call hlt]")
            self.running = False
            self.setpc(0)

        # Deal with instruction exception
        elif instruction.getType() == OPCODE.RET \
                or instruction.getType() == OPCODE.CALL\
                or instruction.getType() == OPCODE.JMP: #jmp???

            new_pc = self.getpc()
            text_start = self.memoryCache[0]['start']
            text_end = self.memoryCache[0]['start'] + self.memoryCache[0]['size']

            for m in self.memoryCache:
                if 'vdso' in m['name']:
                    vdso_start = m['start']
                    vdso_end = m['start'] + m['size']
                    break

            if not self.isAddress(new_pc):
                raise IllegalPcException(self.arch, new_pc)

            if not ((text_start <= new_pc <= text_end) or (vdso_start <= new_pc <= vdso_end)):
                log.info('.text [%s-%s], vdso [%s-%s], new_pc is %s' %
                         (hex(text_start), hex(text_end), hex(vdso_start), hex(vdso_end), hex(new_pc)))

                raise IllegalInstException(self.arch, new_pc)
        '''
        elif instruction.getType() == OPCODE.RET \
                or instruction.getType() == OPCODE.CALL:

            new_pc = self.getpc()
            if not self.isAddress(new_pc):
                self.lastInstType = instruction.getType()
                raise IllegalPcException(self.arch, new_pc)
        '''        
        
        self.lastInstType = instruction.getType()
        self.last_pc = pc
        pc = self.getpc()
        
        return pc


   
    def test(self):
        """Ok, everything is prepared, just go"""
        self.initialize()

        self.log.info("Start emulation")

        pc = self.getpc()
        self.lastInstType = None
        
        while pc:    
            pc = self.process()

        self.log.info("Emulation done")
        return
