#!/usr/bin/env python
# coding=utf-8

from emulator import *

dbg = Debugger('./bin', '/tmp/bin_44621f618fc0a22cafc8ea0753ee1673.dump')
dbg.initialize()
dbg.show_inst = True
while dbg.running:
    # dbg.parse_command()
    dbg.process()
