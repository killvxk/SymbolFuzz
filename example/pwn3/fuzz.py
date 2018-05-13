#!/usr/bin/env python
# coding=utf-8

from emulator import *

binary = './bin'
fuzzer = Fuzzer(binary)
fuzzer.fuzz()
