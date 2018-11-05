#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Guesser.py
Create by: Bluecake
Description: A class to guess function of target code
"""

from triton import OPCODE
from emulator import *
from debugger import *
from pwn import log, context

###############################################################################
#                          Emulation Exception                                #
###############################################################################
class UnsupportedTypeException(Exception):
    def __init__(self, arg):
        if arch == 'x86':
            Exception.__init__(self, "Unsupported arg type %s: %s" % (str(type(arg))), str(arg))
        else:
            raise UnsupportedArchException(arch)


##############################################################################
class FUNCTYPE:
    FUNC_unk = 0
    FUNC_atoi = 1
    FUNC_strlen = 2
    FUNC_printf = 3


func_table = {

    FUNCTYPE.FUNC_atoi: [
        {
            'input' : ["1000\x00"],
            'expect': {'ret':1000}
        },
        {
            'input' : ["  234\x00"],
            'expect': {'ret': 234}
        },
        {
            'input' : ["ABC234\x00"],
            'expect': {'ret':0}
        },
        {
            'input' : ["-1\x00"],
            'expect': {'ret':0xffffffff}
        },
    ],

    # FUNCTYPE.FUNC_strlen: [
    #     {
    #         'input' : ["a\x00"],
    #         'expect': {'ret':1}
    #     },
    #     {
    #         'input' : ["1aa\x2fbd3\x00"],
    #         'expect': {'ret':7}
    #     },
    #     {
    #         'input' : ["\x001aa\x2fbd3\x00"],
    #         'expect': {'ret':0}
    #     },
    # ],

    # FUNCTYPE.FUNC_printf: [
    #     {
    #         'input' : [ "%x\x00", 0xdeadbeaf],
    #         'expect': {'out':'deadbeaf'}
    #     },
    #     {
    #         'input' : [ "%d\x00", 0xdeadbeaf],
    #         'expect': {'out':'3735928495'}
    #     },
    #     {
    #         'input' : [ "%s\x00", "This is a test"],
    #         'expect': {'out':'This is a test'}
    #     },
    # ]
}


###############################################################################                  
#                                  Main Class                                 #
###############################################################################
class Guesser(object):
    """ The target of this module is to guess function of an unknown code

    Attributes:
        
    """

    def __init__(self, binary):
        """ Class Constructor

        Args:
            binary: path of executable binary
        """

        self.binary = binary
        self.emulator = None

        bin_root = os.path.dirname(os.path.abspath(binary))
        self.config_file = bin_root + '/functions.txt'
        self.load_state()

    """
    Store function information info file
    """
    def __del__(self):
        config = (self.func_info, self.call_info)
        try:
            open(self.config_file, 'wb').write(repr(config))
        except Exception as e:
            log.debug(e)

    
    def save_state(self):
        log.info('Guesser save_state called')
        self.__del__()
    
    def load_state(self):
        log.info('Guesser load_state called')
        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            self.func_info, self.call_info = eval(data)
        else:
            self.call_info = {}  # store which function is called
            self.func_info = {}  # store which it is in

    """
    Set arguments in the given stack
    """
    def fillArgs(self, emulator, esp, sample):

        sample_input = sample['input']
        data_addr = esp + 0x100
        arg_addr = esp + 4

        # fill stack with dirty data
        emulator.writeMemory(esp + 4, '\xde\xad\xbe\xaf' * 6)
        emulator.writeMemory(esp, 0xdeadbeaf)

        for index, arg in enumerate(sample_input):

            if type(arg) == str:
                emulator.writeMemory(arg_addr, data_addr)
                emulator.writeMemory(data_addr, arg + "\x00")
                data_addr += len(arg) + 2

            elif type(arg) == int:
                emulator.writeMemory(arg_addr, arg)

            else:
                raise NotImplementedException()
            
            arg_addr += 4

    """
    Check return value of specific input
    """
    def checkResult(self, emulator, sample):

        sample_output = sample['expect']
        for ret_type, value in sample_output.items():

            if ret_type == 'ret':
                ret = emulator.getreg('eax')

                if ret != value:
                    return False

                else:
                    return True

            else:
                raise NotImplementedException()

    
    """
    Test function with give sample
    """
    def checkSample(self, entry, sample):

        # log.info('load dumpfile from guesser.py')
        emulator = Debugger(self.binary)
        # emulator = Emulator(self.binary)
        emulator.initialize()

        emulator.show_inst = False
        emulator.show_output = False
        emulator.dev_zero = True

        esp = emulator.getreg('esp')
        self.fillArgs(emulator, esp, sample)

        emulator.setpc(entry)

        def check_syscall(emulator, *args):
            emulator.running = False

        emulator.add_callback('noImplementSys', check_syscall)

        try:
            while emulator.running:
                emulator.process()
                if emulator.inst_count > 20000:
                    break
        except IllegalPcException as e:
            log.debug(e)

        # except MemoryAccessException as e:
        #     log.info(e)
        #     print e
        
        self.retaddr = emulator.last_pc
        if self.checkResult(emulator, sample):
            return True 

        else:
            return False
         
    
    """
    Check a given function with specific type
    """
    def tryFunc(self, entry, functype):

        samples = func_table[functype] 
        for sample in samples:
            # title('sample', sample)
            if not self.checkSample(entry, sample):
                log.debug('[0x%x] function check failed with sample %s'
                            % (entry, repr(sample['input'])))
                return False
        
            log.info('[0x%x] function check passed with sample %s'
                    % (entry, repr(sample['input'])))
        return True


    """
    Export:
        Speculate the real function with entry of an unknown function
    """
    def guessFunc(self, entry):

        # title('guessFunc', (hex(entry), self.func_info))
        if self.func_info.has_key(entry):
            return self.func_info[entry][0]

        for functype in func_table:
            try:
                if self.tryFunc(entry, functype):
                    self.func_info[entry] = (functype, self.retaddr)
                    return functype
            except IllegalPcException as e:
                log.debug(e)
        
        self.func_info[entry] = (FUNCTYPE.FUNC_unk, 0)
        return FUNCTYPE.FUNC_unk


    """
    Export:
        Speculate the real called function, like call 0x804831(atoi)
    """
    def guessCall(self, pc):
        
        if self.call_info.has_key(pc):
            return self.call_info[pc]

        self.emulator.setpc(pc)
        self.emulator.process()
        entry = self.emulator.getpc()
        functype = self.guessFunc(entry)
        self.call_info[pc] = functype
        return functype
