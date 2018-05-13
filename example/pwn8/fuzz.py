#!/usr/bin/env python
# coding=utf-8

from emulator import *

binary = './pwn8'
fuzzer = Fuzzer(binary, log_level=logging.INFO)
fuzzer.test()
