#!/usr/bin/env python
# coding=utf-8

from emulator import *

dbg = Debugger('./stack')
dbg.initialize()
data = open('./eip.in.stack').read()
dbg.set_input(data)

while dbg.running:
    dbg.parse_command()

