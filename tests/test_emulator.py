#!/usr/bin/env python
# coding=utf-8
import os
import nose
import time
from symbolfuzz import *
from pwn import context, log

# context.log_level = "DEBUG" 
binary_dir = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../binary/'))
def test_emulator():
    binpath = os.path.join(binary_dir, "simple_test")
    nose.tools.assert_equals(os.path.exists(binpath), True)
    
    emu = Debugger(binpath)
    emu.initialize()
    emu.show_inst = False
    emu.show_output = True
    pc = emu.getpc()

    emu.set_input("234567890\n\x00")
    # nose.tools.assert_equals(len(emu.stdin), 4)
    while pc:
        # print hex(pc)
        pc = emu.parse_command()

if __name__ == '__main__':
    test_emulator()
