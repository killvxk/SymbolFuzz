#!/usr/bin/env python
# coding=utf-8

from emulator import *
from pwn import context

binary_dir = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../binary/'))

def test_symbol_fuzzer():
    binary = os.path.join(binary_dir, 'read_execute')
    fuzzer = SymbolFuzzer(binary)
    # fuzzer.fuzz()

    for i in range(5):
        context.log_level = "WARN"
        print fuzzer.get_crash()

def test_symbol_fuzzer_nolog():
    binary = os.path.join(binary_dir, 'read_execute')
    fuzzer = SymbolFuzzer(binary, logv='WARN')
    fuzzer.fuzz()
    try:
        while True:
            print fuzzer.get_crash()
            time.sleep(10)
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    # test_symbol_fuzzer()
    test_symbol_fuzzer_nolog()
